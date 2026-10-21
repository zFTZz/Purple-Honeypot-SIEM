"""
Simulador de ataque do Purple Honeypot SIEM.

Cliente SSH controlado, usado apenas em laboratório para gerar telemetria sem
digitar senhas manualmente. Ele não é o honeypot: conecta ao honeypot em
localhost:2222 e reproduz um fluxo de brute-force seguido de reconhecimento.

Uso:
    python honeypot/simulate_attack.py

Fluxo:
  1. Abre seis conexões com senha incorreta -> seis eventos ssh.login_failed.
  2. Abre uma conexão, erra a primeira senha e acerta a segunda -> ssh.login.
  3. Executa um comando de reconhecimento -> ssh.command.

O IP observado pelo honeypot é 127.0.0.1; portanto, a regra 100103 (origem
externa) não dispara neste teste. Ela é validada separadamente com um IP público.
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
    """Realiza uma tentativa de autenticação e retorna True se o honeypot aceitou."""
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
    """Erra a primeira senha, acerta a segunda (regra do honeypot) e executa o comando."""
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
    parser = argparse.ArgumentParser(description="Simula brute-force e reconhecimento contra o honeypot SSH local.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=2222)
    parser.add_argument("--user", default="root")
    parser.add_argument("--attempts", type=int, default=6, help="Falhas antes do login (default: 6)")
    parser.add_argument("--command", default="whoami", help="Comando de reconhecimento após o login")
    parser.add_argument("--delay", type=float, default=1.0, help="Segundos entre tentativas (default: 1.0)")
    args = parser.parse_args()

    print(f"[*] Atacando {args.host}:{args.port} com {args.attempts} falhas de senha...")
    for i in range(1, args.attempts + 1):
        try:
            aceitou = tentar_senha(args.host, args.port, args.user, f"senha-errada-{i}")
        except (socket.error, paramiko.SSHException) as e:
            print(f"[!] Não foi possível conectar: {e}")
            print("[*] Inicie o honeypot em outro terminal: python honeypot/ssh_honeypot.py")
            return 1
        print(f"    tentativa {i}/{args.attempts}: {'ACEITA (inesperado)' if aceitou else 'falhou'}")
        time.sleep(args.delay)

    print(f"[*] Login e comando de reconhecimento: {args.command}")
    try:
        executar_comando(args.host, args.port, args.user, args.command)
    except (socket.error, paramiko.SSHException) as e:
        print(f"[!] Falha no login/comando: {e}")
        return 1

    print("[+] Ataque simulado concluído. Veja os alertas no Wazuh/Telegram.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
