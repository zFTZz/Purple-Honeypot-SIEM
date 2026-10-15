"""
PROJETO 1 - http_honeypot.py
O que faz: finge ser um painel admin / site com .env exposto pra atrair scanner (nmap, ffuf, Burp).
Captura: IP, metodo, caminho pedido, User-Agent. Tudo em JSON pro Wazuh.
Rodar: python honeypot/http_honeypot.py (porta 8080, abre no browser http://localhost:8080)
"""
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import datetime
import os

PORT = 8080  # 80 exigiria root, 8080 roda normal. No Wazuh voce vai ver scan em /admin /.env /.git
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "http.log")

# Iscas que scanner sempre testa. Se pedir uma dessas, e quase certo que e ataque/recon
CAMINHOS_SUSPEITOS = ("/admin", "/login", "/.env", "/.git", "/config.php", "/backup", "/robots.txt")


def gravar_log(evento: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    evento["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if "src_ip" in evento:
        evento["srcip"] = evento["src_ip"]  # alias p/ same_srcip das regras Wazuh
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")


class Handler(BaseHTTPRequestHandler):
    # Silencia log padrao do http.server (senao polui o terminal)
    def log_message(self, *args):
        return

    def _responder(self, codigo=200, corpo=b"OK", tipo=b"text/plain"):
        self.send_response(codigo)
        self.send_header("Content-Type", tipo.decode())
        self.send_header("Content-Length", str(len(corpo)))
        self.end_headers()
        self.wfile.write(corpo)

    def do_GET(self):
        ip = self.client_address[0]
        user_agent = self.headers.get("User-Agent", "unknown")
        print(f"[HTTP] {ip} GET {self.path}")

        gravar_log({
            "type": "http.request",
            "src_ip": ip,
            "method": "GET",
            "path": self.path,
            "user_agent": user_agent,
            "suspicious": self.path in CAMINHOS_SUSPEITOS or ".." in self.path,
        })

        # Iscas: devolve algo tentador pra atacante continuar e gerar mais log
        if self.path == "/.env":
            self._responder(200, b"DB_PASSWORD=supersecreta123\nAWS_KEY=FAKEKEY123\n")
        elif self.path == "/robots.txt":
            self._responder(200, b"User-agent: *\nDisallow: /admin\n")
        elif self.path.startswith("/admin"):
            self._responder(200, b"<h1>Admin login</h1><form>user:<input><br>pass:<input type=password></form>".decode().encode(),
                            b"text/html")
        else:
            self._responder(200, b"<h1>Loja demo</h1><p>Bem-vindo</p>", b"text/html")

    # POST (ex: /login com user/senha) tambem interessa pro SOC
    def do_POST(self):
        ip = self.client_address[0]
        tamanho = int(self.headers.get("Content-Length", 0))
        corpo = self.rfile.read(tamanho).decode(errors="ignore")[:2000]  # corta pra nao encher disco
        print(f"[HTTP] {ip} POST {self.path} body={corpo[:80]}")
        gravar_log({
            "type": "http.request",
            "src_ip": ip,
            "method": "POST",
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", "unknown"),
            "body": corpo,
            "suspicious": True,  # POST em honeypot sempre trata como suspeito
        })
        self._responder(200, b"OK")


def main():
    servidor = HTTPServer(("0.0.0.0", PORT), Handler)
    print(f"[*] HTTP honeypot em 0.0.0.0:{PORT} -> {LOG_FILE}")
    print(f"[*] teste: http://localhost:{PORT}/  e  http://localhost:{PORT}/.env")
    servidor.serve_forever()


if __name__ == "__main__":
    main()
