from ipaddress import ip_address
import hashlib
import re
from urllib.parse import urlparse

from flask import Flask, render_template, request


def analyze_url(value: str) -> dict[str, object]:
    candidate = value.strip()
    parsed = urlparse(candidate)
    findings: list[str] = []
    score = 0

    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"url": candidate, "risk": "Inválida", "score": 0, "findings": ["Informe uma URL HTTP ou HTTPS válida."]}

    hostname = parsed.hostname.lower()
    if parsed.scheme == "http":
        findings.append("A conexão não usa HTTPS.")
        score += 2
    if parsed.username or parsed.password:
        findings.append("A URL contém credenciais embutidas.")
        score += 3
    if "@" in parsed.netloc:
        findings.append("O caractere @ pode ocultar o destino real.")
        score += 2
    if hostname.startswith("xn--") or ".xn--" in hostname:
        findings.append("O domínio usa representação Punycode.")
        score += 2
    try:
        ip_address(hostname)
    except ValueError:
        pass
    else:
        findings.append("O destino é um endereço IP, não um domínio.")
        score += 2
    if len(candidate) > 120:
        findings.append("A URL é excepcionalmente longa.")
        score += 1

    risk = "Baixo" if score <= 1 else "Moderado" if score <= 3 else "Alto"
    if not findings:
        findings.append("Nenhum sinal básico de risco foi identificado.")
    return {"url": candidate, "risk": risk, "score": score, "findings": findings}


def analyze_ssh_logs(log_text: str) -> dict[str, object]:
    failures: list[dict[str, str]] = []
    source_ips: set[str] = set()
    pattern = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<ip>\S+)"
    )
    source_pattern = re.compile(r"\bfrom (?P<ip>\S+)")

    for line in log_text.splitlines():
        source_match = source_pattern.search(line)
        if source_match:
            candidate_ip = source_match.group("ip").rstrip(",")
            try:
                ip_address(candidate_ip)
            except ValueError:
                pass
            else:
                source_ips.add(candidate_ip)

        match = pattern.search(line)
        if match:
            failures.append(
                {"user": match.group("user"), "ip": match.group("ip")}
            )

    by_ip: dict[str, int] = {}
    for failure in failures:
        ip = failure["ip"]
        by_ip[ip] = by_ip.get(ip, 0) + 1

    top_attacker = max(by_ip, key=by_ip.get) if by_ip else None
    total_failures = len(failures)
    risk = "Baixo" if total_failures < 5 else "Moderado" if total_failures < 10 else "Alto"
    return {
        "total_failures": total_failures,
        "unique_ips": len(source_ips),
        "top_attacker": top_attacker,
        "top_attacker_attempts": by_ip.get(top_attacker, 0) if top_attacker else 0,
        "risk": risk,
    }


def compare_file_integrity(original: str, current: str) -> dict[str, object]:
    original_hash = hashlib.sha256(original.encode("utf-8")).hexdigest()
    current_hash = hashlib.sha256(current.encode("utf-8")).hexdigest()
    return {
        "original_hash": original_hash,
        "current_hash": current_hash,
        "changed": original_hash != current_hash,
        "status": "Alterado" if original_hash != current_hash else "Íntegro",
    }


def analyze_password(password: str) -> dict[str, object]:
    findings: list[str] = []
    score = 0
    common_passwords = {"123456", "password", "senha", "qwerty", "admin"}

    if password.lower() in common_passwords:
        findings.append("A senha está entre padrões muito comuns.")
        score = 0
    else:
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            findings.append("Use pelo menos 8 caracteres.")

        character_groups = [
            bool(re.search(r"[a-z]", password)),
            bool(re.search(r"[A-Z]", password)),
            bool(re.search(r"\d", password)),
            bool(re.search(r"[^A-Za-z0-9]", password)),
        ]
        score += sum(character_groups)
        if sum(character_groups) < 3:
            findings.append("Combine letras maiúsculas, minúsculas, números e símbolos.")
        if len(set(password.lower())) < max(4, len(password) // 3):
            findings.append("Evite repetir excessivamente os mesmos caracteres.")

    strength = "Fraca" if score <= 2 else "Moderada" if score <= 4 else "Forte"
    if not findings:
        findings.append("A senha atende aos critérios básicos de complexidade.")
    return {"strength": strength, "score": score, "findings": findings}


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        tools = [
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
        ]
        return render_template("index.html", tools=tools)

    @app.route("/tools/url-analyzer", methods=["GET", "POST"])
    def url_analyzer():
        result = None
        if request.method == "POST":
            result = analyze_url(request.form.get("url", ""))
        return render_template("url_analyzer.html", result=result)

    @app.route("/tools/ssh-log-analyzer", methods=["GET", "POST"])
    def ssh_log_analyzer():
        result = None
        if request.method == "POST":
            result = analyze_ssh_logs(request.form.get("logs", ""))
        return render_template("ssh_log_analyzer.html", result=result)

    @app.route("/tools/integrity-monitor", methods=["GET", "POST"])
    def integrity_monitor():
        result = None
        if request.method == "POST":
            result = compare_file_integrity(
                request.form.get("original", ""),
                request.form.get("current", ""),
            )
        return render_template("integrity_monitor.html", result=result)

    @app.route("/tools/password-analyzer", methods=["GET", "POST"])
    def password_analyzer():
        result = None
        if request.method == "POST":
            result = analyze_password(request.form.get("password", ""))
        return render_template("password_analyzer.html", result=result)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
