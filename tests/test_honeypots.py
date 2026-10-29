"""Testes dos três honeypots: sobem o protocolo de verdade e conferem a telemetria.

Cada teste inicia o servidor em uma porta efêmera (nunca 2222/8080/2121) e
redireciona o log para o `tmp_path`, então a suíte não briga com um honeypot já
rodando na máquina nem suja `honeypot/logs/`.

O contrato verificado aqui é o que as regras do Wazuh consomem: um JSON por
linha, `type` esperado por protocolo, `src_ip` com alias `srcip` e timestamp UTC
em ISO 8601 terminando em `Z`.
"""
import datetime
import socket
import threading

import pytest


def _validar_evento_comum(evento, tipo_esperado):
    assert evento["type"] == tipo_esperado
    assert evento["src_ip"] == evento["srcip"], "alias srcip divergente do src_ip"
    assert evento["timestamp"].endswith("Z"), "timestamp precisa ser UTC com sufixo Z"
    # fromisoformat só aceita "+00:00"; se não converter, é porque não terminou em Z.
    momento = datetime.datetime.fromisoformat(evento["timestamp"].replace("Z", "+00:00"))
    assert momento.tzinfo is not None
    assert momento.utcoffset() == datetime.timedelta(0)


# --------------------------------------------------------------------------- HTTP

@pytest.fixture
def servidor_http(http_honeypot, tmp_path, monkeypatch):
    log = tmp_path / "http.log"
    monkeypatch.setattr(http_honeypot, "LOG_FILE", str(log))
    servidor = http_honeypot.ThreadingHTTPServer(("127.0.0.1", 0), http_honeypot.Handler)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    try:
        yield servidor, log
    finally:
        servidor.shutdown()
        servidor.server_close()
        thread.join(timeout=5)


def _porta(servidor):
    return servidor.server_address[1]


def test_http_registra_get_logo_como_nao_suspeito(servidor_http, ler_log, esperar_eventos):
    import urllib.request

    servidor, log = servidor_http
    with urllib.request.urlopen(f"http://127.0.0.1:{_porta(servidor)}/", timeout=5) as resp:
        assert resp.status == 200

    assert esperar_eventos(lambda: len(ler_log(log)) == 1)
    evento = ler_log(log)[0]
    _validar_evento_comum(evento, "http.request")
    assert evento["method"] == "GET"
    assert evento["path"] == "/"
    assert evento["suspicious"] is False
    assert "user_agent" in evento


def test_http_registra_isca_env_como_suspeita(servidor_http, ler_log, esperar_eventos):
    import urllib.request

    servidor, log = servidor_http
    with urllib.request.urlopen(f"http://127.0.0.1:{_porta(servidor)}/.env", timeout=5) as resp:
        corpo = resp.read().decode()

    # A isca precisa devolver conteúdo tentador (fictício) para o scanner continuar.
    assert "DB_PASSWORD" in corpo and "AWS_KEY" in corpo
    assert "supersecreta123" in corpo

    assert esperar_eventos(lambda: len(ler_log(log)) == 1)
    evento = ler_log(log)[0]
    assert evento["path"] == "/.env"
    assert evento["suspicious"] is True


def test_http_registra_post_com_corpo_e_sempre_suspeito(servidor_http, ler_log, esperar_eventos):
    import urllib.request

    servidor, log = servidor_http
    requisicao = urllib.request.Request(
        f"http://127.0.0.1:{_porta(servidor)}/login",
        data=b"user=admin&pass=tentativa",
        method="POST",
    )
    with urllib.request.urlopen(requisicao, timeout=5) as resp:
        assert resp.status == 200

    assert esperar_eventos(lambda: len(ler_log(log)) == 1)
    evento = ler_log(log)[0]
    assert evento["method"] == "POST"
    assert evento["suspicious"] is True
    assert "user=admin" in evento["body"]


def test_http_limita_o_corpo_registrado(servidor_http, ler_log, esperar_eventos):
    import urllib.request

    servidor, log = servidor_http
    corpo = b"a" * 5000
    requisicao = urllib.request.Request(
        f"http://127.0.0.1:{_porta(servidor)}/login", data=corpo, method="POST"
    )
    with urllib.request.urlopen(requisicao, timeout=5) as resp:
        resp.read()

    assert esperar_eventos(lambda: len(ler_log(log)) == 1)
    # O honeypot corta em 2000 caracteres para não encher o disco.
    assert len(ler_log(log)[0]["body"]) == 2000


# ---------------------------------------------------------------------------- FTP

@pytest.fixture
def servidor_ftp(ftp_honeypot, tmp_path, monkeypatch):
    log = tmp_path / "ftp.log"
    monkeypatch.setattr(ftp_honeypot, "LOG_FILE", str(log))
    servidor = ftp_honeypot.ServidorFTP(("127.0.0.1", 0), ftp_honeypot.FTPHandler)
    thread = threading.Thread(target=servidor.serve_forever, daemon=True)
    thread.start()
    try:
        yield servidor, log
    finally:
        servidor.shutdown()
        servidor.server_close()
        thread.join(timeout=5)


def _ler_linha(arquivo):
    linha = arquivo.readline().decode(errors="ignore").rstrip("\r\n")
    assert linha, "servidor FTP fechou a conexão sem responder"
    return linha


def test_ftp_primeira_senha_falha_segunda_entra_e_comandos_sao_logados(
    servidor_ftp, ler_log, esperar_eventos
):
    servidor, log = servidor_ftp
    conexao = socket.create_connection(("127.0.0.1", servidor.server_address[1]), timeout=5)
    arquivo = conexao.makefile("rwb")
    try:
        assert _ler_linha(arquivo).startswith("220")

        arquivo.write(b"USER admin\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("331")

        # 1ª senha sempre falha: é o que alimenta a regra 100109/100110.
        arquivo.write(b"PASS senha-errada\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("530")

        arquivo.write(b"PASS qualquer-outra\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("230")

        arquivo.write(b"PWD\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("257")

        arquivo.write(b"LIST /\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("150")
        assert _ler_linha(arquivo).startswith("226")

        arquivo.write(b"RETR backup.tar.gz\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("150")
        assert _ler_linha(arquivo).startswith("226")

        arquivo.write(b"SITE HELP\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("502")

        arquivo.write(b"QUIT\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("221")
    finally:
        arquivo.close()
        conexao.close()

    assert esperar_eventos(lambda: len(ler_log(log)) >= 5)
    eventos = ler_log(log)

    falhas = [e for e in eventos if e["type"] == "ftp.login_failed"]
    logins = [e for e in eventos if e["type"] == "ftp.login"]
    comandos = [e for e in eventos if e["type"] == "ftp.command"]

    assert len(falhas) == 1
    _validar_evento_comum(falhas[0], "ftp.login_failed")
    assert falhas[0]["user"] == "admin"
    assert falhas[0]["password"] == "senha-errada"

    assert len(logins) == 1
    assert logins[0]["password"] == "qualquer-outra"

    comandos_logados = [e["command"] for e in comandos]
    assert "LIST /" in comandos_logados
    assert "RETR backup.tar.gz" in comandos_logados
    assert "SITE HELP" in comandos_logados, "comando desconhecido precisa ser logado (revela a ferramenta)"


def test_ftp_lista_e_retr_exigem_login(servidor_ftp, ler_log):
    servidor, log = servidor_ftp
    conexao = socket.create_connection(("127.0.0.1", servidor.server_address[1]), timeout=5)
    arquivo = conexao.makefile("rwb")
    try:
        _ler_linha(arquivo)  # banner
        arquivo.write(b"LIST /\r\n")
        arquivo.flush()
        assert _ler_linha(arquivo).startswith("530")
    finally:
        arquivo.close()
        conexao.close()

    assert ler_log(log) == [], "LIST antes do login não deve gerar evento ftp.command"


# ---------------------------------------------------------------------------- SSH

def test_responder_simula_os_comandos_de_reconhecimento(ssh_honeypot):
    responder = ssh_honeypot.responder
    assert responder("whoami") == "root\r\n"
    assert responder("id").startswith("uid=0(root)")
    assert responder("hostname") == "prod-web-01\r\n"
    assert responder("uname -a").startswith("Linux prod-web-01")
    assert responder("ls -la") == responder("ls")
    assert responder("cat id_rsa").startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert responder("cat /root/id_rsa").startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert responder("cat config.env").startswith("DB_PASSWORD=")
    assert "No such file or directory" in responder("cat /etc/hosts")
    assert responder("rm -rf /") == "command not found\r\n"


@pytest.fixture
def servidor_ssh(ssh_honeypot, tmp_path, monkeypatch):
    """Sobe o loop de aceitação do honeypot SSH sem chamar main() (porta fixa)."""
    paramiko = pytest.importorskip("paramiko")

    log = tmp_path / "ssh.log"
    monkeypatch.setattr(ssh_honeypot, "LOG_FILE", str(log))
    host_key = paramiko.RSAKey.generate(2048)

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(10)
    listener.settimeout(0.2)
    porta = listener.getsockname()[1]

    parar = threading.Event()

    def aceitar():
        while not parar.is_set():
            try:
                conexao, endereco = listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(
                target=ssh_honeypot.lidar, args=(conexao, endereco, host_key), daemon=True
            ).start()

    thread = threading.Thread(target=aceitar, daemon=True)
    thread.start()
    try:
        yield porta, log
    finally:
        parar.set()
        thread.join(timeout=5)
        listener.close()


def test_ssh_falha_primeira_senha_loga_login_e_comando(servidor_ssh, ler_log, esperar_eventos):
    paramiko = pytest.importorskip("paramiko")
    porta, log = servidor_ssh

    # Tentativa isolada que deve falhar (base da regra 100100/100101).
    transporte = paramiko.Transport(("127.0.0.1", porta))
    transporte.start_client(timeout=10)
    try:
        with pytest.raises(paramiko.AuthenticationException):
            transporte.auth_password("root", "senha-errada-1")
    finally:
        transporte.close()

    # Mesma conexão: a primeira falha, a segunda autentica (regra do honeypot).
    transporte = paramiko.Transport(("127.0.0.1", porta))
    transporte.start_client(timeout=10)
    try:
        with pytest.raises(paramiko.AuthenticationException):
            transporte.auth_password("root", "senha-errada-2")
        transporte.auth_password("root", "senha-errada-3")

        canal = transporte.open_session(timeout=10)
        canal.exec_command("whoami")
        assert esperar_eventos(
            lambda: any(e["type"] == "ssh.command" for e in ler_log(log))
        )
        canal.close()
    finally:
        transporte.close()

    assert esperar_eventos(
        lambda: len([e for e in ler_log(log) if e["type"] == "ssh.login_failed"]) == 2
    )
    eventos = ler_log(log)

    falhas = [e for e in eventos if e["type"] == "ssh.login_failed"]
    for evento in falhas:
        _validar_evento_comum(evento, "ssh.login_failed")
        assert evento["user"] == "root"

    logins = [e for e in eventos if e["type"] == "ssh.login"]
    assert len(logins) == 1, "a segunda senha da conexão precisa autenticar"
    assert logins[0]["src_ip"] == "127.0.0.1"

    comandos = [e for e in eventos if e["type"] == "ssh.command"]
    assert comandos[0]["command"] == "whoami"
    assert comandos[0]["user"] == "root"


def test_ssh_cada_conexao_nova_volta_a_falhar_a_primeira_senha(servidor_ssh, ler_log, esperar_eventos):
    """A regra é por conexão, não global: ferramentas que abrem 1 conexão por
    tentativa (Hydra) precisam gerar várias falhas."""
    paramiko = pytest.importorskip("paramiko")
    porta, log = servidor_ssh

    for indice in range(3):
        transporte = paramiko.Transport(("127.0.0.1", porta))
        transporte.start_client(timeout=10)
        try:
            with pytest.raises(paramiko.AuthenticationException):
                transporte.auth_password("admin", f"tentativa-{indice}")
        finally:
            transporte.close()

    assert esperar_eventos(
        lambda: len([e for e in ler_log(log) if e["type"] == "ssh.login_failed"]) == 3
    )
    senhas = [e["password"] for e in ler_log(log) if e["type"] == "ssh.login_failed"]
    assert senhas == ["tentativa-0", "tentativa-1", "tentativa-2"]
