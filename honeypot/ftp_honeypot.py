"""
Honeypot FTP do Purple Honeypot SIEM.

Simula um servidor FTP com banner e autenticação, além de iscas para comandos
de listagem e transferência. A primeira senha de cada conexão é rejeitada de
propósito; as seguintes são aceitas. IP, usuário, senha e comandos são
registrados em JSON com timestamp UTC.

Uso:
    python honeypot/ftp_honeypot.py
    ftp admin@localhost -p 2121
"""
import json
import datetime
import os
import socket
import socketserver
import threading

PORT = 2121
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "ftp.log")

# Arquivo fictício exibido em LIST/RETR para simular um servidor comprometido.
ARQUIVO_FALSO = b"-rw-r--r-- 1 root root 482 Jan 15 2024 backup.tar.gz\n"


def gravar_log(evento: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    evento["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if "src_ip" in evento:
        evento["srcip"] = evento["src_ip"]  # alias usado pelas regras de correlação
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")


class FTPHandler(socketserver.StreamRequestHandler):
    def _responder(self, codigo: int, msg: str = ""):
        """Envia uma resposta no formato FTP: 'CÓDIGO mensagem\\r\\n'."""
        linha = f"{codigo} {msg}\r\n"
        self.wfile.write(linha.encode())
        self.wfile.flush()

    def handle(self):
        ip = self.client_address[0]
        usuario = None
        tentativas = 0  # contador de senha nesta conexão (a primeira sempre falha)

        try:
            self._responder(220, "PurpleFTP (vsftpd 3.0.5)")

            while True:
                linha = self.rfile.readline()
                if not linha:
                    break
                comando = linha.decode(errors="ignore").strip()
                if not comando:
                    continue
                partes = comando.split(" ", 1)
                cmd = partes[0].upper()
                arg = partes[1] if len(partes) > 1 else ""

                if cmd == "USER":
                    usuario = arg or "anonymous"
                    tentativas = 0
                    print(f"[FTP] {ip} USER {usuario}")
                    self._responder(331, "Please specify the password.")

                elif cmd == "PASS":
                    senha = arg
                    tentativas += 1
                    # A primeira senha de cada conexão falha de propósito, como no honeypot SSH.
                    if tentativas == 1:
                        gravar_log({
                            "type": "ftp.login_failed",
                            "src_ip": ip,
                            "user": usuario or "anonymous",
                            "password": senha,
                        })
                        print(f"[FTP] {ip} LOGIN FALHOU usuário={usuario} senha=***")
                        self._responder(530, "Login incorrect.")
                    else:
                        gravar_log({
                            "type": "ftp.login",
                            "src_ip": ip,
                            "user": usuario or "anonymous",
                            "password": senha,
                        })
                        print(f"[FTP] {ip} LOGIN OK user={usuario}")
                        self._responder(230, "Login successful.")

                elif cmd == "PWD":
                    self._responder(257, '"/" is the current directory')

                elif cmd in ("SYST",):
                    self._responder(215, "UNIX Type: L8")

                elif cmd in ("FEAT", "OPTS"):
                    self._responder(200, "Features: EPSV UTF8")

                elif cmd == "TYPE":
                    self._responder(200, "Type set to I.")

                elif cmd == "PASV":
                    # Abre um socket de dados efêmero e devolve o endereço no modo passivo.
                    dados = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dados.bind(("0.0.0.0", 0))
                    dados.listen(1)
                    porta = dados.getsockname()[1]
                    threading.Thread(target=self._aceitar_dados, args=(dados,), daemon=True).start()
                    a, b = divmod(porta, 256)
                    ip_local = "127,0,0,1"  # suficiente para testes locais
                    self._responder(227, f"Entering Passive Mode ({ip_local},{a},{b}).")

                elif cmd in ("LIST", "NLST"):
                    if tentativas == 0:
                        self._responder(530, "Please login with USER and PASS.")
                        continue
                    arquivo = arg
                    gravar_log({
                        "type": "ftp.command",
                        "src_ip": ip,
                        "user": usuario or "anonymous",
                        "command": f"{cmd} {arquivo}".strip(),
                    })
                    print(f"[FTP] {ip} COMANDO {cmd} {arquivo}")
                    self._responder(150, "Here comes the directory listing.")
                    # dados enviados pelo socket de dados; se fechado, segue o fluxo
                    self._responder(226, "Directory send OK.")

                elif cmd == "RETR":
                    if tentativas == 0:
                        self._responder(530, "Please login with USER and PASS.")
                        continue
                    gravar_log({
                        "type": "ftp.command",
                        "src_ip": ip,
                        "user": usuario or "anonymous",
                        "command": f"RETR {arg}",
                    })
                    print(f"[FTP] {ip} COMANDO RETR {arg}")
                    self._responder(150, "Opening BINARY mode data connection for backup.tar.gz (482 bytes).")
                    self._responder(226, "Transfer complete.")

                elif cmd in ("QUIT", "EXIT"):
                    self._responder(221, "Goodbye.")
                    break

                else:
                    # Comandos desconhecidos também são registrados e revelam comportamento da ferramenta.
                    gravar_log({
                        "type": "ftp.command",
                        "src_ip": ip,
                        "user": usuario or "-",
                        "command": comando,
                    })
                    self._responder(502, "Command not implemented.")

        except (ConnectionResetError, BrokenPipeError, TimeoutError):
            pass
        finally:
            try:
                self.connection.close()
            except Exception:
                pass

    def _aceitar_dados(self, dados: socket.socket):
        """Aceita a conexão de dados do modo passivo e descarta o payload."""
        try:
            conn, _ = dados.accept()
            conn.settimeout(2.0)
            try:
                conn.recv(4096)
            except Exception:
                pass
            conn.close()
        except Exception:
            pass
        finally:
            dados.close()


class ServidorFTP(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def main():
    servidor = ServidorFTP(("0.0.0.0", PORT), FTPHandler)
    print(f"[*] FTP honeypot em 0.0.0.0:{PORT} -> {LOG_FILE}")
    print("[*] teste: ftp admin@localhost -p 2121 (1ª senha falha, 2ª entra)")
    print("[*] iscas: LIST / RETR mostram arquivo falso backup.tar.gz")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] encerrando FTP honeypot")
        servidor.shutdown()


if __name__ == "__main__":
    main()
