"""
PROJETO 1 - ssh_honeypot.py v2 (SSH DE VERDADE)
Agora aceita o comando `ssh` real, nao so python/nc.
Como: usa paramiko pra fazer o handshake cripto igual OpenSSH. 1a senha SEMPRE falha
(igual server real), da 2a em diante aceita QUALQUER senha e grava tudo.
Rodar: python honeypot/ssh_honeypot.py -> ssh admin@localhost -p 2222 (senha qualquer)
"""
import socket
import threading
import json
import datetime
import os
import paramiko

HOST = "0.0.0.0"
PORT = 2222
LOG_FILE = os.path.join(os.path.dirname(__file__), "logs", "ssh.log")
KEY_FILE = os.path.join(os.path.dirname(__file__), "host.key")

FAKE_KEY = (
    "-----BEGIN OPENSSH PRIVATE KEY-----\r\n"
"b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAABlwAAAAdzc2gtcn\r\n"
"NhAAAAAwEAAQAAAAYEAm11b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7\r\n"
"RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v\r\n"
"8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6v\r\n"
"GvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8\r\n"
"v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7R\r\n"
"kX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8\r\n"
"X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vG\r\n"
"vL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v\r\n"
"7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7Rk\r\n"
"X9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X\r\n"
"9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGv\r\n"
"L8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7\r\n"
"rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX\r\n"
"9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9\r\n"
"N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL\r\n"
"8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7r\r\n"
"K8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9\r\n"
"N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N\r\n"
"7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8\r\n"
"Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK8h7RkX9N/9v8X9N7b6vGvL8Z9Z8v7rK\r\n"
"-----END OPENSSH PRIVATE KEY-----\r\n"
)

FAKE_RESPONSES = {
    "whoami": "root\r\n",
    "id": "uid=0(root) gid=0(root) groups=0(root)\r\n",
    "hostname": "prod-web-01\r\n",
    "uname -a": "Linux prod-web-01 5.15.0-generic x86_64 GNU/Linux\r\n",
    "uname": "Linux\r\n",
    "ls": "app.py  config.env  id_rsa\r\n",
    "pwd": "/root\r\n",
    "cat id_rsa": FAKE_KEY,
    "cat config.env": "DB_PASSWORD=supersecreta123\r\nAWS_KEY=FAKEKEY123\r\n",
    "cat app.py": "print('hello prod')\r\n",
}


def responder(comando: str) -> str:
    """Resposta fake com suporte a 'cat arquivo' e 'ls -la' que atacante sempre tenta."""
    if comando in FAKE_RESPONSES:
        return FAKE_RESPONSES[comando]
    if comando.startswith("cat "):
        alvo = comando[4:].strip()
        if alvo in ("id_rsa", "./id_rsa", "/root/id_rsa"):
            return FAKE_KEY
        if alvo in ("config.env", "./config.env"):
            return FAKE_RESPONSES["cat config.env"]
        return f"cat: {alvo}: No such file or directory\r\n"
    if comando.startswith("ls"):
        return FAKE_RESPONSES["ls"]  # ls, ls -la, ls -l caem aqui
    return "command not found\r\n"


def gravar_log(evento: dict):
    os.makedirs(os.path.dirname(LOG_FILE), exist_ok=True)
    evento["timestamp"] = datetime.datetime.now(datetime.timezone.utc).isoformat().replace("+00:00", "Z")
    if "src_ip" in evento:
        evento["srcip"] = evento["src_ip"]  # alias p/ same_srcip das regras Wazuh
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")


def get_host_key():
    """Chave do servidor falso. SSH real exige chave, entao geramos 1 vez e reusamos."""
    if not os.path.exists(KEY_FILE):
        print("[*] gerando host.key (1 vez)...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_FILE)
    return paramiko.RSAKey(filename=KEY_FILE)


class ServidorFake(paramiko.ServerInterface):
    """Decide o que o atacante pode fazer. Aqui: pode tudo, so anotamos."""
    def __init__(self, ip):
        self.ip = ip
        self.user = "unknown"
        self.tentativas = 0

    def check_auth_password(self, username, password):
        # DECISAO: 1a tentativa SEMPRE falha (igual server real com senha errada).
        # Hydra abre 1 conexao por tentativa = cada try vira 1 ssh.login_failed (bruteforce real no log).
        # Manual: erra a 1a, entra na 2a. Sem falha nao existe regra de bruteforce.
        self.tentativas += 1
        self.user = username
        if self.tentativas == 1:
            gravar_log({"type": "ssh.login_failed", "src_ip": self.ip, "user": username, "password": password})
            print(f"[FALHA] {self.ip} user={username} pass={password}")
            return paramiko.AUTH_FAILED
        gravar_log({"type": "ssh.login", "src_ip": self.ip, "user": username, "password": password})
        print(f"[LOGIN] {self.ip} user={username} pass={password}")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Aceita pedido de terminal do ssh real pra sumir o "PTY allocation failed"
        return True

    def check_channel_exec_request(self, channel, command):
        # Atacante mandou `ssh user@host 'id'` sem abrir terminal: loga tambem
        cmd = command.decode(errors="ignore") if isinstance(command, bytes) else str(command)
        gravar_log({"type": "ssh.command", "src_ip": self.ip, "user": self.user, "command": cmd.strip()})
        return True


def lidar(conn, addr, host_key):
    ip = addr[0]
    print(f"[+] {ip} conectou")
    try:
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        server = ServidorFake(ip)
        t.start_server(server=server)
        canal = t.accept(20)  # espera o atacante abrir sessao por ate 20s
        if canal is None:
            return
        canal.send(b"Welcome to Ubuntu 22.04 LTS\r\n# ")
        buf = b""
        while True:
            dados = canal.recv(1024)
            if not dados:
                break
            buf += dados
            # espera Enter (\r ou \n) pra fechar o comando
            if b"\n" in buf or b"\r" in buf:
                comando = buf.decode(errors="ignore").strip().replace("\r", "").replace("\n", "")
                buf = b""
                if comando in ("exit", "quit", "logout"):
                    break
                if not comando:
                    canal.send(b"# ")
                    continue
                print(f"[{ip}] $ {comando}")
                gravar_log({"type": "ssh.command", "src_ip": ip, "user": server.user, "command": comando})
                canal.send(responder(comando).encode() + b"# ")
        canal.close()
        t.close()
    except Exception as e:
        print(f"[-] {ip}: {e}")
    finally:
        try:
            conn.close()
        except Exception:
            pass
        print(f"[*] {ip} desconectou, voltando a ouvir...")


def main():
    host_key = get_host_key()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((HOST, PORT))
    s.listen(10)
    s.settimeout(1.0)  # timeout pra Ctrl+C funcionar no Windows (accept travava sem isso)
    print(f"[*] SSH REAL ouvindo {HOST}:{PORT} -> teste: ssh admin@localhost -p {PORT}")
    print(f"[*] PS1 e o SERVIDOR (nao digita nada aqui, so Ctrl+C pra parar)")
    try:
        while True:
            try:
                conn, addr = s.accept()
            except socket.timeout:
                continue
            threading.Thread(target=lidar, args=(conn, addr, host_key), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] parando servidor...")
    finally:
        s.close()


if __name__ == "__main__":
    main()
