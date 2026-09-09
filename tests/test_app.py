from app import analyze_ssh_logs, analyze_url, compare_file_integrity, create_app


def test_analyze_url_flags_http_and_embedded_credentials():
    result = analyze_url("http://admin:secret@example.com/login")

    assert result["risk"] == "Alto"
    assert "A conexão não usa HTTPS." in result["findings"]
    assert "A URL contém credenciais embutidas." in result["findings"]


def test_analyze_url_accepts_safe_https_url():
    result = analyze_url("https://example.com")

    assert result["risk"] == "Baixo"
    assert result["findings"] == ["Nenhum sinal básico de risco foi identificado."]


def test_url_analyzer_renders_analysis_result():
    client = create_app().test_client()

    response = client.post("/tools/url-analyzer", data={"url": "https://example.com"})

    assert response.status_code == 200
    assert b"Risco Baixo" in response.data


def test_analyze_ssh_logs_counts_attempts_by_ip():
    logs = "\n".join(
        [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for invalid user admin from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.11 port 22 ssh2",
            "Accepted password for analyst from 192.0.2.12 port 22 ssh2",
        ]
    )

    result = analyze_ssh_logs(logs)

    assert result["total_failures"] == 3
    assert result["unique_ips"] == 3
    assert result["top_attacker"] == "192.0.2.10"
    assert result["top_attacker_attempts"] == 2


def test_ssh_log_analyzer_renders_analysis_result():
    client = create_app().test_client()

    response = client.post(
        "/tools/ssh-log-analyzer",
        data={
            "logs": "Failed password for root from 192.0.2.10 port 22 ssh2",
        },
    )

    assert response.status_code == 200
    assert b">Risco<" in response.data
    assert b">Falhas<" in response.data


def test_compare_file_integrity_detects_changes():
    result = compare_file_integrity("versao original", "versao alterada")

    assert result["changed"] is True
    assert result["status"] == "Alterado"
    assert result["original_hash"] != result["current_hash"]


def test_integrity_monitor_renders_hashes():
    client = create_app().test_client()

    response = client.post(
        "/tools/integrity-monitor",
        data={"original": "config=ok", "current": "config=changed"},
    )

    assert response.status_code == 200
    assert b">Status<" in response.data
    assert b"Alterado" in response.data
