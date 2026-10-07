import pytest

from app import (
    analyze_password,
    analyze_ssh_logs,
    analyze_url,
    compare_file_integrity,
    create_app,
    decode_base64,
    extract_iocs,
    generate_password,
    validate_email,
)


def test_analyze_url_flags_http_and_embedded_credentials():
    resultado = analyze_url("http://admin:secret@example.com/login")

    assert resultado["risk"] == "Alto"
    assert "A conexão não usa HTTPS." in resultado["findings"]
    assert "A URL contém credenciais embutidas." in resultado["findings"]


def test_analyze_url_accepts_safe_https_url():
    resultado = analyze_url("https://example.com")

    assert resultado["risk"] == "Baixo"
    assert resultado["findings"] == ["Nenhum sinal básico de risco foi identificado."]


def test_url_analyzer_renders_analysis_result():
    cliente = create_app().test_client()

    resposta = cliente.post("/tools/url-analyzer", data={"url": "https://example.com"})

    assert resposta.status_code == 200
    assert b"Baixo" in resposta.data
    assert b"RESULTADO" in resposta.data


def test_analyze_ssh_logs_counts_attempts_by_ip():
    logs = "\n".join(
        [
            "Failed password for root from 192.0.2.10 port 22 ssh2",
            "Failed password for invalid user admin from 192.0.2.10 port 22 ssh2",
            "Failed password for root from 192.0.2.11 port 22 ssh2",
            "Accepted password for analyst from 192.0.2.12 port 22 ssh2",
        ]
    )

    resultado = analyze_ssh_logs(logs)

    assert resultado["total_failures"] == 3
    assert resultado["unique_ips"] == 3
    assert resultado["top_attacker"] == "192.0.2.10"
    assert resultado["top_attacker_attempts"] == 2


def test_ssh_log_analyzer_renders_analysis_result():
    cliente = create_app().test_client()

    resposta = cliente.post(
        "/tools/ssh-log-analyzer",
        data={
            "logs": "Failed password for root from 192.0.2.10 port 22 ssh2",
        },
    )

    assert resposta.status_code == 200
    assert b">Risco<" in resposta.data
    assert b">Falhas<" in resposta.data


def test_compare_file_integrity_detects_changes():
    resultado = compare_file_integrity("versao original", "versao alterada")

    assert resultado["changed"] is True
    assert resultado["status"] == "Alterado"
    assert resultado["original_hash"] != resultado["current_hash"]


def test_integrity_monitor_renders_hashes():
    cliente = create_app().test_client()

    resposta = cliente.post(
        "/tools/integrity-monitor",
        data={"original": "config=ok", "current": "config=changed"},
    )

    assert resposta.status_code == 200
    assert b">Status<" in resposta.data
    assert b"Alterado" in resposta.data


def test_analyze_password_flags_common_password():
    resultado = analyze_password("password")

    assert resultado["strength"] == "Fraca"
    assert "padrões muito comuns" in resultado["findings"][0]


@pytest.mark.parametrize(
    ("senha", "pontuacao_esperada", "forca_esperada"),
    [
        ("", 0, "Fraca"),
        ("aaa", 1, "Fraca"),
        ("abcdefgh", 2, "Fraca"),
        ("Abcdefgh", 3, "Moderada"),
        ("Abcdefg1", 4, "Moderada"),
        ("Abcdef1!", 5, "Forte"),
        ("Teste123!Ab", 5, "Forte"),
        ("Teste123!Abc", 6, "Forte"),
        ("PASSWORD", 0, "Fraca"),
    ],
)
def test_password_score_matches_criteria_and_scale(senha, pontuacao_esperada, forca_esperada):
    resultado = analyze_password(senha)

    assert resultado["score"] == pontuacao_esperada
    assert resultado["strength"] == forca_esperada
    assert resultado["max_score"] == 6
    assert 0 <= resultado["score"] <= resultado["max_score"]
    assert sum(criterio["points"] for criterio in resultado["criteria"]) == resultado["score"]
    assert sum(criterio["max_points"] for criterio in resultado["criteria"]) == resultado["max_score"]


def test_password_analyzer_does_not_render_password():
    cliente = create_app().test_client()
    senha = "Senha-Forte-2026!"

    resposta = cliente.post("/tools/password-analyzer", data={"password": senha})

    assert resposta.status_code == 200
    assert senha.encode() not in resposta.data
    assert b"For\xc3\xa7a Estimada" in resposta.data
    assert b"Forte" in resposta.data
    assert b">6/6</strong>" in resposta.data
    assert "Como a pontuação é calculada" in resposta.get_data(as_text=True)


def test_generate_password_respects_length_and_character_groups():
    senha = generate_password(24)

    assert len(senha) == 24
    assert any(caractere.islower() for caractere in senha)
    assert any(caractere.isupper() for caractere in senha)
    assert any(caractere.isdigit() for caractere in senha)
    assert any(caractere in "!#$%&()*+,-./:;<=>?@[\\]^_`{|}~" for caractere in senha)


def test_password_generator_rejects_invalid_length():
    cliente = create_app().test_client()

    resposta = cliente.post(
        "/tools/password-generator",
        data={"length": "4", "include_symbols": "on"},
    )

    assert resposta.status_code == 200
    assert b"entre 8 e 128" in resposta.data


def test_extract_iocs_groups_unique_indicators():
    resultado = extract_iocs(
        "Conexão para https://malware.example.test/login de 203.0.113.10 "
        "e contato soc@example.test. Hash "
        "0123456789abcdef0123456789abcdef."
    )

    assert resultado["ips"] == ["203.0.113.10"]
    assert resultado["urls"] == ["https://malware.example.test/login"]
    assert resultado["emails"] == ["soc@example.test"]
    assert resultado["hashes"] == ["0123456789abcdef0123456789abcdef"]


def test_base64_decoder_returns_utf8_text():
    assert decode_base64("U2VjdVRvb2xz") == "SecuTools"


def test_base64_decoder_shows_invalid_input_error():
    cliente = create_app().test_client()

    resposta = cliente.post("/tools/base64-decoder", data={"value": "not-base64"})

    assert resposta.status_code == 200
    assert b"Base64 v\xc3\xa1lido" in resposta.data


def test_validate_email_accepts_valid_format():
    resultado = validate_email("user@example.com")

    assert resultado["valid"] is True
    assert resultado["status"] == "Válido"


def test_validate_email_rejects_invalid_format():
    resultado = validate_email("not-an-email")

    assert resultado["valid"] is False
    assert resultado["status"] == "Inválido"
    assert "O formato não segue o padrão de e-mail válido." in resultado["findings"]


def test_validate_email_detects_common_domains():
    resultado = validate_email("user@gmail.com")

    assert resultado["valid"] is True
    assert any("comum" in observacao for observacao in resultado["findings"])


def test_email_validator_renders_validation_result():
    cliente = create_app().test_client()

    resposta = cliente.post("/tools/email-validator", data={"email": "test@example.com"})

    assert resposta.status_code == 200
    assert b"V\xc3\xa1lido" in resposta.data
