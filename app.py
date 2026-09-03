"""Ponto de entrada da aplicação SecuTools."""

from flask import Flask, render_template


def create_app() -> Flask:
    app = Flask(__name__)

    @app.get("/")
    def index():
        tools = [
            {
                "name": "Analisador de URLs",
                "description": "Analise e desarme links suspeitos.",
                "status": "Em breve",
            },
            {
                "name": "Analisador de Logs",
                "description": "Identifique padrões de força bruta em logs SSH.",
                "status": "Em breve",
            },
            {
                "name": "Monitor de Integridade",
                "description": "Detecte alterações em arquivos monitorados.",
                "status": "Em breve",
            },
        ]
        return render_template("index.html", tools=tools)

    return app


app = create_app()


if __name__ == "__main__":
    app.run(debug=True)
