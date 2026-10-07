<p align="center">
  <img src="static/img/logo.png" alt="SecuTools" width="240">
</p>

---

<p align="center">
  Ferramentas de Segurança da Informação em um só lugar.
  <br>
  Um projeto de portfólio para transformar conceitos de segurança em aplicações práticas.
</p>

<p align="center">
  <strong>Python · Flask · HTML · CSS · JavaScript</strong>
  <br>
  8 ferramentas disponíveis · Interface em português · Em desenvolvimento
</p>

---

### Sobre o projeto

O **SecuTools** é uma aplicação web que reúne ferramentas para examinar links, interpretar registros de acesso, comparar conteúdos e trabalhar com senhas e dados de investigação.

A proposta é facilitar pequenas tarefas de análise por meio de uma interface simples: o usuário escolhe uma ferramenta, informa os dados e recebe um resultado organizado, sem precisar utilizar o terminal.

O projeto foi desenvolvido com foco no aprendizado e na aplicação de conceitos de **segurança defensiva** — a área dedicada a identificar sinais de problemas e apoiar a proteção de sistemas. As ferramentas são acessadas por páginas próprias, permitindo ampliar a plataforma de forma incremental.

---

### Conheça as ferramentas

### Analisador de URLs

Ajuda a reconhecer características de um link que merecem atenção antes de abri-lo. O usuário cola o endereço e recebe uma classificação de risco, acompanhada das observações encontradas.

**Exemplo de uso:** analisar um link recebido por mensagem e verificar se ele usa uma conexão sem HTTPS ou apresenta uma estrutura incomum.

A ferramenta examina o endereço sem visitar o site. A classificação considera sinais básicos e não garante que um link seja seguro ou malicioso.

### Analisador de Logs

Logs são registros de acontecimentos em um sistema. Esta ferramenta lê registros de acesso SSH — um recurso usado para acessar computadores remotamente — e resume tentativas de entrada com senha incorreta.

**Exemplo de uso:** colar um trecho de registro de um servidor para descobrir quantas tentativas falharam, quantos endereços de origem aparecem e qual origem concentrou mais falhas.

O resultado ajuda a perceber tentativas repetidas de adivinhar senhas. A análise considera o trecho fornecido pelo usuário.

### Monitor de Integridade

Compara duas versões de um texto para verificar se houve alguma alteração. Para isso, cria uma espécie de **impressão digital do conteúdo**, chamada hash, e compara os resultados.

**Exemplo de uso:** colar a versão original e a versão atual de uma configuração para descobrir se continuam iguais. Até um espaço ou uma letra diferente altera o resultado.

Nesta versão, a comparação usa textos inseridos nos campos da página. A ferramenta não acompanha arquivos ou pastas automaticamente.

### Analisador de Senhas

Avalia características de uma senha, como comprimento e presença de letras maiúsculas, minúsculas, números e símbolos. Apresenta uma pontuação de **0 a 6**, uma classificação de força e sugestões de melhoria.

**Exemplo de uso:** comparar senhas fictícias e entender por que uma combinação curta e repetitiva recebe uma avaliação inferior.

A avaliação considera critérios básicos de complexidade. A aplicação não salva a senha informada nem a exibe novamente no resultado.

### Gerador de Senhas

Cria senhas aleatórias com letras maiúsculas, minúsculas e números, além de símbolos opcionais. O usuário escolhe o tamanho, entre **8 e 128 caracteres**.

**Exemplo de uso:** gerar uma combinação de 16 caracteres em vez de criar uma senha baseada em nomes, datas ou sequências previsíveis.

A geração utiliza um recurso do Python próprio para aleatoriedade em segurança. A aplicação não mantém um histórico das senhas geradas.

### Extrator de IOCs

**IOC** significa *Indicador de Comprometimento*: uma informação que pode servir como pista durante a investigação de um incidente de segurança.

A ferramenta encontra e organiza **endereços IP, domínios, links, e-mails e hashes** em um texto, removendo repetições dentro de cada categoria. Endereços IP identificam pontos na rede; domínios são nomes de sites; hashes são impressões digitais de conteúdos.

**Exemplo de uso:** colar um relatório com vários endereços misturados e obter listas separadas para facilitar a consulta.

A extração reconhece padrões de escrita. Encontrar um indicador não significa que ele seja malicioso.

### Decodificador Base64

Converte um texto representado em Base64 de volta para sua forma legível. Base64 é uma maneira de representar dados usando letras, números e alguns símbolos; não é uma forma de criptografia.

**Exemplo de uso:** informar `U2VjdVRvb2xz` e receber `SecuTools` como resultado.

A ferramenta aceita conteúdos que, após a conversão, possam ser lidos como texto UTF-8, um formato que permite representar letras e caracteres acentuados.

### Validador de E-mail

Verifica características do formato de um endereço de e-mail e apresenta observações sobre possíveis problemas de escrita.

**Exemplo de uso:** analisar `analista@example.com` e conferir se o endereço atende aos critérios básicos de formato avaliados pela aplicação.

A ferramenta não envia mensagens e não confirma se a caixa de e-mail existe ou pertence a alguém.

## Experiência de uso

- **Página inicial com oito cards:** quatro por linha em telas maiores, com adaptação para duas ou uma coluna em telas menores.
- **Navegação entre ferramentas:** navbar presente nas páginas dos módulos, com destaque para a ferramenta atual.
- **Menu responsivo:** navegação adaptada para celular, com transição suave ao abrir e fechar.
- **Resultados organizados:** classificações, observações e listas apresentadas conforme a finalidade de cada ferramenta.
- **Tema escuro:** identidade visual com detalhes em ciano e interface em português.

## Tecnologias utilizadas

| Tecnologia | Papel no projeto |
| --- | --- |
| **Python** | Executa as análises, comparações e conversões. |
| **Flask e Jinja** | Conectam os formulários às ferramentas e montam as páginas com os resultados. |
| **HTML e CSS** | Estruturam as páginas e definem a aparência e a adaptação às telas. |
| **JavaScript** | Controla o comportamento e as interações da navbar. |
| **Pytest** | Verifica o comportamento das funções e das páginas com testes automatizados. |
| **Gunicorn** | Permite executar a aplicação em um ambiente de hospedagem. |

As operações de segurança utilizam principalmente recursos da biblioteca padrão do Python, como cálculo de hashes, geração de senhas e conversão Base64.

## Competências demonstradas

- Desenvolvimento de uma aplicação web com integração entre interface e processamento em Python.
- Aplicação prática de conceitos de segurança: análise de links, registros de acesso, integridade de conteúdos e indicadores de investigação.
- Organização de ferramentas em funções de análise e páginas próprias.
- Validação de entradas e tratamento de erros nas ferramentas de conversão Base64 e geração de senhas.
- Construção de uma interface responsiva com navegação interativa.
- Uso de testes automatizados e versionamento com Git.

## Como os dados são processados

As análises são executadas pelo **servidor Flask da própria aplicação**, sem consultas a serviços externos de análise ou reputação. O projeto não possui banco de dados nem implementa armazenamento dos conteúdos enviados.

Ao executar o projeto no próprio computador, o processamento ocorre nessa máquina. Ao acessar uma versão hospedada, os dados dos formulários são enviados ao servidor da hospedagem para processamento.

## Como executar no computador

O ambiente de desenvolvimento do projeto utiliza **Python 3.14**. Os comandos abaixo são para Linux e macOS.

### 1. Baixe o projeto

```bash
git clone https://github.com/christzph/secutools.git
cd secutools
```

### 2. Crie e ative um ambiente virtual

O ambiente virtual mantém as dependências do projeto separadas dos demais programas em Python.

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instale as dependências e inicie a aplicação

```bash
python -m pip install -r requirements.txt
python app.py
```

Abra **[http://127.0.0.1:5000](http://127.0.0.1:5000)** no navegador.

Esse comando inicia o modo de desenvolvimento. Para executar com Gunicorn em um ambiente compatível:

```bash
gunicorn app:app --bind 0.0.0.0:8000
```

Nesse caso, o endereço local é **[http://127.0.0.1:8000](http://127.0.0.1:8000)**.

## Testes automatizados

Com o ambiente virtual ativo e as dependências instaladas:

```bash
python -m pytest -q tests/test_app.py
```

## Estrutura do projeto

```text
secutools/
├── app.py              # Aplicação Flask, funções de análise e rotas
├── requirements.txt    # Dependências do projeto
├── templates/          # Páginas da home e das ferramentas
├── static/
│   ├── style.css       # Estilos e layout responsivo
│   ├── navbar.js       # Interações da navegação
│   └── img/
│       └── logo.png    # Logo do projeto
├── tests/
│   └── test_app.py     # Testes automatizados
└── README.md
```

