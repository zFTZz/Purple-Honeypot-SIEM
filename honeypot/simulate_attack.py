"""
Simulador de ataque para o laboratorio do Projeto 1.

Ele NAO e o honeypot: e um "atacante" controlado que fala SSH de verdade com o
honeypot em localhost:2222. Serve para gerar os eventos reais de brute-force e
de reconhecimento sem precisar digitar senha 6 vezes na mao.

Uso (com o honeypot rodando em outro terminal):
    python honeypot/simulate_attack.py

Fluxo:
  1. Abre 6 conexoes e erra a senha em cada uma -> 6x ssh.login_failed.
  2. Abre uma conexao, erra a 1a senha e acerta a 2a -> ssh.login.
  3. Executa um comando de reconhecimento -> ssh.command.

O IP visto pelo honeypot sera 127.0.0.1, entao a regra 100103 (origem externa)
nao dispara neste teste; ela e validada separadamente com um IP externo.
"""
import argparse
import socket
import time

import paramiko


def conectar(host, port):
    t = paramiko.Transport((host, port))
    t.start_client(timeout=5)
    return t


def tentar_senha(host, port, user, password):
    """Uma tentativa de autenticacao. Retorna True se o honeypot aceitou."""
    t = conectar(host, port)
    try:
        try:
            t.auth_password(user, password)
            return True
        except paramiko.AuthenticationException:
            return False
    finally:
        t.close()


def executar_comando(host, port, user, command):
    """Erra a 1a senha, acerta a 2a (regra do honeypot) e executa o comando."""
    t = conectar(host, port)
    try:
        try:
            t.auth_password(user, "primeira-senha-errada")
        except paramiko.AuthenticationException:
            pass

        t.auth_password(user, "segunda-senha-qualquer")
        canal = t.open_session()
        canal.exec_command(command)
        time.sleep(0.4)
        canal.close()
    finally:
        t.close()


def main():
    parser = argparse.ArgumentParser(description="Simula brute-force + recon contra o honeypot SSH local.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--attempts", type=int, default=6, help="Falhas antes do login (default: 6)")
    parser.add_argument("--command", default="whoami", help="Comando de recon apos o login")
    parser.add_argument("--delay", type=float, default=1.0, help="Segundos entre tentativas (default: 1.0)")
    args = parser.parse_args()

    print(f"[*] Atacando {args.host}:{args.port} com {args.attempts} falhas de senha...")
    for i in range(1, args.attempts + 1):
        try:
            aceitou = tentar_senha(args.host, args.port, args.user, f"senha-errada-{i}")
        except (socket.error, paramiko.SSHException) as e:
            print(f"[!] Nao consegui conectar: {e}")
            print("[*] Inicie o honeypot em outro terminal: python honeypot/ssh_honeypot.py")
            return 1
        print(f"    tentativa {i}/{args.attempts}: {'ACEITA (inesperado)' if aceitou else 'falhou'}")
        time.sleep(args.delay)

    print(f"[*] Login + comando de recon: {args.command}")
    try:
        executar_comando(args.host, args.port, args.user, args.command)
    except (socket.error, paramiko.SSHException) as e:
        print(f"[!] Falha no login/comando: {e}")
        return 1

    print("[+] Ataque simulado concluido. Veja os alertas no Wazuh/Telegram.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
