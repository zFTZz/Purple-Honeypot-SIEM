"""
PROJETO 1 - ftp_honeypot.py
O que faz: finge ser um servidor FTP anônimo/senhas fracas pra atrair bots
(Masscan+FTP, Hydra, Mirai variante ftp). Mesma logica do SSH: 1a senha da
conexao sempre falha (gera ftp.login_failed), da 2a em diante aceita qualquer.
Captura: IP, usuario, senha, comandos FTP. Tudo em JSON pro Wazuh.
Rodar: python honeypot/ftp_honeypot.py (porta 2121; 21 exigiria privilegio)
Teste: ftp anonymous@localhost -p 2121  (ou curl ftp://localhost:2121 -u anon:x)
Porta 2121 porque a 21 so funciona como admin/root no Windows.
"""
import json
import datetime
import os
import socket
import socketserver
import threading

PORT = 2121
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "ftp.log")

# Arquivos falsos q o atacante espera achar (vsftpd "comprometido")
ARQUIVO_FALSO = b"-rw-r--r-- 1 root root 482 Jan 15 2024 backup.tar.gz\n"


def gravar_log(evento: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    evento["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if "src_ip" in evento:
        evento["srcip"] = evento["src_ip"]  # alias p/ same_source_ip das regras Wazuh
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")


class FTPHandler(socketserver.StreamRequestHandler):
    def _responder(self, codigo: int, msg: str = ""):
        """Padrao FTP: 'CODIGO mensagem\\r\\n'"""
        linha = f"{codigo} {msg}\r\n"
        self.wfile.write(linha.encode())
        self.wfile.flush()

    def handle(self):
        ip = self.client_address[0]
        usuario = None
        tentativas = 0  # contador de senha nesta conexao (1a sempre falha)

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
                    # 1a senha de cada conexao falha de proposito (mesma logica do SSH honeypot)
                    if tentativas == 1:
                        gravar_log({
                            "type": "ftp.login_failed",
                            "src_ip": ip,
                            "user": usuario or "anonymous",
                            "password": senha,
                        })
                        print(f"[FTP] {ip} LOGIN FALHOU user={usuario} senha={senha}")
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
                    # Abre um socket de dados efêmero e devolve o endereço (modo passivo)
                    dados = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    dados.bind(("0.0.0.0", 0))
                    dados.listen(1)
                    porta = dados.getsockname()[1]
                    threading.Thread(target=self._aceitar_dados, args=(dados,), daemon=True).start()
                    a, b = divmod(porta, 256)
                    ip_local = self.client_address[0] if False else "127,0,0,1"
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
                    # Comando desconhecido tambem vira log (revela ferramenta/behavior)
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
        """Aceita a conexao de dados do modo passivo e descarta o payload."""
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
    print("[*] teste: ftp admin@localhost -p 2121 (1a senha falha, 2a entra)")
    print("[*] iscas: LIST / RETR mostram arquivo falso backup.tar.gz")
    try:
        servidor.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] encerrando FTP honeypot")
        servidor.shutdown()


if __name__ == "__main__":
    main()
