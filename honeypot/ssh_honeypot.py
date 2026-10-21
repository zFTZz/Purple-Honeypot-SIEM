"""
Honeypot SSH do Purple Honeypot SIEM.

Implementa um servidor SSH real com Paramiko para capturar tentativas de
autenticação e comandos executados em um shell simulado. A primeira senha de
cada conexão é rejeitada de propósito; as seguintes são aceitas, gerando
telemetria para as regras de brute-force e reconhecimento.

Uso:
    python honeypot/ssh_honeypot.py
    ssh admin@localhost -p 2222
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
    "-----BEGIN OPENSSH PRIVATE KEY-----\n"
    "conteudo-ficticio-para-isca\n"
    "-----END OPENSSH PRIVATE KEY-----\n"
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
    """Retorna uma resposta simulada para os comandos mais comuns de reconhecimento."""
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
        evento["srcip"] = evento["src_ip"]  # alias usado pelas regras de correlação
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(evento) + "\n")


def get_host_key():
    """Gera e reutiliza a chave RSA do servidor SSH simulado."""
    if not os.path.exists(KEY_FILE):
        print("[*] gerando host.key (1 vez)...")
        key = paramiko.RSAKey.generate(2048)
        key.write_private_key_file(KEY_FILE)
    return paramiko.RSAKey(filename=KEY_FILE)


class ServidorFake(paramiko.ServerInterface):
    """Define a política de autenticação e sessão do honeypot."""
    def __init__(self, ip):
        self.ip = ip
        self.user = "unknown"
        self.tentativas = 0

    def check_auth_password(self, username, password):
        # A primeira tentativa de cada conexão falha de propósito para gerar
        # telemetria de brute-force. Ferramentas como Hydra costumam abrir uma
        # conexão por tentativa; no teste manual, erre a primeira senha e use a segunda.
        self.tentativas += 1
        self.user = username
        if self.tentativas == 1:
            gravar_log({"type": "ssh.login_failed", "src_ip": self.ip, "user": username, "password": password})
            print(f"[FALHA] {self.ip} usuário={username} senha=***")
            return paramiko.AUTH_FAILED
        gravar_log({"type": "ssh.login", "src_ip": self.ip, "user": username, "password": password})
        print(f"[LOGIN] {self.ip} usuário={username} senha=***")
        return paramiko.AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED if kind == "session" else paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_channel_shell_request(self, channel):
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        # Aceita a alocação de PTY para compatibilidade com o cliente OpenSSH.
        return True

    def check_channel_exec_request(self, channel, command):
        # Registra comandos enviados em modo não interativo (ssh host 'id').
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
        canal = t.accept(20)  # aguarda a abertura de sessão por até 20 segundos
        if canal is None:
            return
        canal.send(b"Welcome to Ubuntu 22.04 LTS\r\n# ")
        buf = b""
        while True:
            dados = canal.recv(1024)
            if not dados:
                break
            buf += dados
            # Aguarda Enter (\r ou \n) para delimitar o comando.
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
    s.settimeout(1.0)  # timeout para permitir Ctrl+C no Windows
    print(f"[*] Honeypot SSH ouvindo {HOST}:{PORT} | teste: ssh admin@localhost -p {PORT}")
    print("[*] Este terminal é o servidor; use Ctrl+C para encerrar.")
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
