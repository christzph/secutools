from ipaddress import ip_address
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
    pattern = re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from "
        r"(?P<ip>\S+)"
    )

    for line in log_text.splitlines():
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
        "unique_ips": len(by_ip),
        "top_attacker": top_attacker,
        "top_attacker_attempts": by_ip.get(top_attacker, 0) if top_attacker else 0,
        "risk": risk,
    }


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
                "status": "Em breve",
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

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
