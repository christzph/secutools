import base64
import hashlib
import re
import secrets
import string
from ipaddress import ip_address
from urllib.parse import urlparse

from flask import Flask, render_template, request


def analyze_url(valor: str) -> dict[str, object]:
    url_informada = valor.strip()
    partes_url = urlparse(url_informada)
    observacoes = []
    pontuacao = 0

    if partes_url.scheme not in {"http", "https"} or not partes_url.hostname:
        return {
            "url": url_informada,
            "risk": "Inválida",
            "score": 0,
            "findings": ["Informe uma URL HTTP ou HTTPS válida."],
        }

    dominio = partes_url.hostname.lower()
    if partes_url.scheme == "http":
        observacoes.append("A conexão não usa HTTPS.")
        pontuacao += 2
    if partes_url.username or partes_url.password:
        observacoes.append("A URL contém credenciais embutidas.")
        pontuacao += 3
    if "@" in partes_url.netloc:
        observacoes.append("O caractere @ pode ocultar o destino real.")
        pontuacao += 2
    if dominio.startswith("xn--") or ".xn--" in dominio:
        observacoes.append("O domínio usa representação Punycode.")
        pontuacao += 2
    try:
        ip_address(dominio)
    except ValueError:
        pass
    else:
        observacoes.append("O destino é um endereço IP, não um domínio.")
        pontuacao += 2
    if len(url_informada) > 120:
        observacoes.append("A URL é excepcionalmente longa.")
        pontuacao += 1

    if pontuacao <= 1:
        risco = "Baixo"
    elif pontuacao <= 3:
        risco = "Moderado"
    else:
        risco = "Alto"

    if not observacoes:
        observacoes.append("Nenhum sinal básico de risco foi identificado.")
    return {
        "url": url_informada,
        "risk": risco,
        "score": pontuacao,
        "findings": observacoes,
    }


def analyze_ssh_logs(texto_logs: str) -> dict[str, object]:
    falhas = []
    ips_origem = set()
    padrao_falha = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<ip>\S+)"
    )
    padrao_origem = re.compile(r"\bfrom (?P<ip>\S+)")

    for linha in texto_logs.splitlines():
        origem_encontrada = padrao_origem.search(linha)
        if origem_encontrada:
            ip_encontrado = origem_encontrada.group("ip").rstrip(",")
            try:
                ip_address(ip_encontrado)
            except ValueError:
                pass
            else:
                ips_origem.add(ip_encontrado)

        falha_encontrada = padrao_falha.search(linha)
        if falha_encontrada:
            falhas.append(
                {
                    "user": falha_encontrada.group("user"),
                    "ip": falha_encontrada.group("ip"),
                }
            )

    tentativas_por_ip = {}
    for falha in falhas:
        ip = falha["ip"]
        if ip not in tentativas_por_ip:
            tentativas_por_ip[ip] = 0
        tentativas_por_ip[ip] += 1

    ip_principal = None
    tentativas_principais = 0
    for ip, tentativas in tentativas_por_ip.items():
        if tentativas > tentativas_principais:
            ip_principal = ip
            tentativas_principais = tentativas

    total_falhas = len(falhas)
    if total_falhas < 5:
        risco = "Baixo"
    elif total_falhas < 10:
        risco = "Moderado"
    else:
        risco = "Alto"

    return {
        "total_failures": total_falhas,
        "unique_ips": len(ips_origem),
        "top_attacker": ip_principal,
        "top_attacker_attempts": tentativas_principais,
        "risk": risco,
    }


def compare_file_integrity(original: str, atual: str) -> dict[str, object]:
    hash_original = hashlib.sha256(original.encode("utf-8")).hexdigest()
    hash_atual = hashlib.sha256(atual.encode("utf-8")).hexdigest()
    alterado = hash_original != hash_atual

    if alterado:
        situacao = "Alterado"
    else:
        situacao = "Íntegro"

    return {
        "original_hash": hash_original,
        "current_hash": hash_atual,
        "changed": alterado,
        "status": situacao,
    }


def analyze_password(senha: str) -> dict[str, object]:
    observacoes = []
    senhas_comuns = {"123456", "password", "senha", "qwerty", "admin"}
    senha_comum = senha.lower() in senhas_comuns

    if len(senha) >= 12:
        pontos_comprimento = 2
    elif len(senha) >= 8:
        pontos_comprimento = 1
    else:
        pontos_comprimento = 0

    grupos_caracteres = [
        ("Letras minúsculas", bool(re.search(r"[a-z]", senha))),
        ("Letras maiúsculas", bool(re.search(r"[A-Z]", senha))),
        ("Números", bool(re.search(r"\d", senha))),
        ("Símbolos", bool(re.search(r"[^A-Za-z0-9]", senha))),
    ]
    criterios = [
        {
            "label": "Comprimento: 8 a 11 caracteres vale 1 ponto; 12 ou mais vale 2",
            "points": pontos_comprimento,
            "max_points": 2,
        }
    ]
    total_grupos = 0
    for descricao, presente in grupos_caracteres:
        if presente:
            pontos = 1
            total_grupos += 1
        else:
            pontos = 0
        criterios.append({"label": descricao, "points": pontos, "max_points": 1})

    if senha_comum:
        observacoes.append("A senha está entre padrões muito comuns. A pontuação foi zerada.")
        for criterio in criterios:
            criterio["points"] = 0
    else:
        if len(senha) < 8:
            observacoes.append("Use pelo menos 8 caracteres.")
        if total_grupos < 3:
            observacoes.append("Combine letras maiúsculas, minúsculas, números e símbolos.")
        if len(set(senha.lower())) < max(4, len(senha) // 3):
            observacoes.append("Evite repetir excessivamente os mesmos caracteres.")

    pontuacao = 0
    pontuacao_maxima = 0
    for criterio in criterios:
        pontuacao += criterio["points"]
        pontuacao_maxima += criterio["max_points"]

    if pontuacao <= 2:
        forca = "Fraca"
    elif pontuacao <= 4:
        forca = "Moderada"
    else:
        forca = "Forte"

    if not observacoes:
        observacoes.append("A senha atende aos critérios básicos de complexidade.")
    return {
        "strength": forca,
        "score": pontuacao,
        "max_score": pontuacao_maxima,
        "criteria": criterios,
        "findings": observacoes,
    }


def generate_password(comprimento: int, incluir_simbolos: bool = True) -> str:
    if comprimento < 8 or comprimento > 128:
        raise ValueError("O comprimento deve estar entre 8 e 128 caracteres.")

    grupos = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if incluir_simbolos:
        grupos.append(string.punctuation)

    senha = []
    for grupo in grupos:
        senha.append(secrets.choice(grupo))

    caracteres_disponiveis = "".join(grupos)
    caracteres_restantes = comprimento - len(senha)
    for _ in range(caracteres_restantes):
        senha.append(secrets.choice(caracteres_disponiveis))

    secrets.SystemRandom().shuffle(senha)
    return "".join(senha)


def extract_iocs(texto: str) -> dict[str, list[str]]:
    padroes = {
        "ips": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "domains": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b",
        "urls": r"https?://[^\s<>'\"]+",
        "emails": r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        "hashes": r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{8}|[a-fA-F0-9]{32})?\b",
    }
    resultados = {}
    for categoria, padrao in padroes.items():
        ocorrencias = re.findall(padrao, texto, flags=re.IGNORECASE)
        resultados[categoria] = []
        indicadores_encontrados = set()
        for indicador in ocorrencias:
            if indicador not in indicadores_encontrados:
                resultados[categoria].append(indicador)
                indicadores_encontrados.add(indicador)
    return resultados


def decode_base64(valor: str) -> str:
    valor_sem_espacos = re.sub(r"\s+", "", valor)
    try:
        conteudo_decodificado = base64.b64decode(valor_sem_espacos, validate=True)
        return conteudo_decodificado.decode("utf-8")
    except (ValueError, UnicodeDecodeError) as erro:
        raise ValueError("Informe um valor Base64 válido contendo texto UTF-8.") from erro


def validate_email(email: str) -> dict[str, object]:
    email = email.strip().lower()
    observacoes = []
    pontuacao = 0
    valido = True

    padrao = r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}$"
    if not re.match(padrao, email):
        observacoes.append("O formato não segue o padrão de e-mail válido.")
        valido = False
    else:
        pontuacao += 1
        parte_local, dominio = email.rsplit("@", 1)

        if len(parte_local) > 64:
            observacoes.append("A parte antes do @ excede 64 caracteres.")
        elif len(parte_local) < 1:
            observacoes.append("A parte local está vazia.")
        else:
            pontuacao += 1

        if ".." in email:
            observacoes.append("Contém pontos consecutivos (padrão inválido).")
        if email.startswith(".") or email.startswith("@"):
            observacoes.append("Começa com caractere inválido.")
        if email.endswith("."):
            observacoes.append("Termina com ponto.")

        dominios_comuns = {"gmail.com", "hotmail.com", "outlook.com", "yahoo.com"}
        if dominio in dominios_comuns:
            observacoes.append(f"Domínio '{dominio}' é comum; verifique se é esperado em seu contexto.")

    if valido and pontuacao >= 2:
        situacao = "Válido"
    else:
        situacao = "Inválido"

    if not observacoes:
        observacoes.append("O e-mail atende aos critérios básicos de validação.")
    return {"status": situacao, "findings": observacoes, "valid": valido}


def create_app() -> Flask:
    aplicacao = Flask(__name__)

    ferramentas = [
        {
            "name": "Analisador de URLs",
            "description": "Identifique sinais básicos de risco em links.",
            "status": "Disponível",
            "url": "/tools/url-analyzer",
        },
        {
            "name": "Analisador de Logs",
            "description": "Identifique padrões de força bruta em logs SSH.",
            "status": "Disponível",
            "url": "/tools/ssh-log-analyzer",
        },
        {
            "name": "Monitor de Integridade",
            "description": "Detecte alterações em arquivos monitorados.",
            "status": "Disponível",
            "url": "/tools/integrity-monitor",
        },
        {
            "name": "Analisador de Senhas",
            "description": "Avalie a força de uma senha sem armazená-la.",
            "status": "Disponível",
            "url": "/tools/password-analyzer",
        },
        {
            "name": "Gerador de Senhas",
            "description": "Gere senhas aleatórias com aleatoriedade segura.",
            "status": "Disponível",
            "url": "/tools/password-generator",
        },
        {
            "name": "Extrator de IOCs",
            "description": "Encontre IPs, domínios, URLs, e-mails e hashes.",
            "status": "Disponível",
            "url": "/tools/ioc-extractor",
        },
        {
            "name": "Decodificador Base64",
            "description": "Converta Base64 para texto localmente.",
            "status": "Disponível",
            "url": "/tools/base64-decoder",
        },
        {
            "name": "Validador de Email",
            "description": "Valide e-mails com verificações de padrão e segurança.",
            "status": "Disponível",
            "url": "/tools/email-validator",
        },
    ]

    @aplicacao.get("/")
    def index():
        return render_template("index.html", tools=ferramentas, show_tools_menu=False)

    @aplicacao.route("/tools/url-analyzer", methods=["GET", "POST"])
    def url_analyzer():
        resultado = None
        if request.method == "POST":
            url = request.form.get("url", "")
            resultado = analyze_url(url)
        return render_template(
            "url_analyzer.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/ssh-log-analyzer", methods=["GET", "POST"])
    def ssh_log_analyzer():
        resultado = None
        if request.method == "POST":
            logs = request.form.get("logs", "")
            resultado = analyze_ssh_logs(logs)
        return render_template(
            "ssh_log_analyzer.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/integrity-monitor", methods=["GET", "POST"])
    @aplicacao.route("/tools/integrity-monitor", methods=["GET", "POST"])
    def integrity_monitor():
        resultado = None
        if request.method == "POST":
            original = request.form.get("original", "")
            atual = request.form.get("current", "")
            resultado = compare_file_integrity(original, atual)
        return render_template(
            "integrity_monitor.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/password-analyzer", methods=["GET", "POST"])
    def password_analyzer():
        resultado = None
        if request.method == "POST":
            senha = request.form.get("password", "")
            resultado = analyze_password(senha)
        return render_template(
            "password_analyzer.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/password-generator", methods=["GET", "POST"])
    def password_generator():
        resultado = None
        erro = None
        if request.method == "POST":
            try:
                comprimento = int(request.form.get("length", "16"))
            except ValueError:
                erro = "Informe um comprimento numérico."
            else:
                incluir_simbolos = request.form.get("include_symbols") == "on"
                try:
                    resultado = generate_password(comprimento, incluir_simbolos)
                except ValueError as erro_capturado:
                    erro = str(erro_capturado)
        return render_template(
            "password_generator.html",
            result=resultado,
            error=erro,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/ioc-extractor", methods=["GET", "POST"])
    def ioc_extractor():
        resultado = None
        if request.method == "POST":
            texto = request.form.get("text", "")
            resultado = extract_iocs(texto)
        return render_template(
            "ioc_extractor.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/base64-decoder", methods=["GET", "POST"])
    def base64_decoder():
        resultado = None
        erro = None
        if request.method == "POST":
            valor = request.form.get("value", "")
            try:
                resultado = decode_base64(valor)
            except ValueError as erro_capturado:
                erro = str(erro_capturado)
        return render_template(
            "base64_decoder.html",
            result=resultado,
            error=erro,
            tools=ferramentas,
            show_tools_menu=True,
        )

    @aplicacao.route("/tools/email-validator", methods=["GET", "POST"])
    def email_validator():
        resultado = None
        if request.method == "POST":
            email = request.form.get("email", "")
            resultado = validate_email(email)
        return render_template(
            "email_validator.html",
            result=resultado,
            tools=ferramentas,
            show_tools_menu=True,
        )

    return aplicacao


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
