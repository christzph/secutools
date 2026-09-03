from app import analyze_url, create_app


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
