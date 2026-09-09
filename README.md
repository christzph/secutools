# SecuTools

Plataforma web modular para ferramentas de Segurança da Informação.

O projeto será desenvolvido incrementalmente, com foco em Blue Team, SOC,
resposta a incidentes, automação e GRC.

## Status

Em desenvolvimento.

- Stack atual: Flask 3 e Python 3.14 em `.venv`.
- Aplicação: `app.py`, com factory `create_app()` e rota inicial `/`.
- Módulo disponível: Analisador de URLs em `/tools/url-analyzer`.
- A análise é local e não acessa o destino da URL. Ela identifica HTTP sem
  criptografia, credenciais embutidas, `@`, Punycode, IP direto e URLs longas.
- Módulo disponível: Analisador de Logs SSH em `/tools/ssh-log-analyzer`.
- A análise de logs é local e contabiliza falhas de autenticação, todos os IPs
  de origem encontrados e o IP com mais tentativas malsucedidas.
- Módulo disponível: Monitor de Integridade em `/tools/integrity-monitor`.
- A comparação calcula hashes SHA-256 de dois conteúdos fornecidos pelo usuário,
  sem acessar caminhos arbitrários do sistema.
- Módulo disponível: Analisador de Senhas em `/tools/password-analyzer`.
- A avaliação é local e não armazena nem exibe novamente a senha informada.
- Módulo disponível: Gerador de Senhas em `/tools/password-generator`.
- As senhas são geradas localmente com o módulo criptograficamente seguro
  `secrets` e não são armazenadas pela aplicação.
- Módulo disponível: Extrator de IOCs em `/tools/ioc-extractor`.
- A extração identifica IPs, domínios, URLs, e-mails e hashes sem consultas
  externas.
- Módulo disponível: Decodificador Base64 em `/tools/base64-decoder`.
- A decodificação aceita texto UTF-8 e é executada localmente.
- Testes: `pytest -q tests/test_app.py`.
