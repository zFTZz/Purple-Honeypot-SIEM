#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Projeto 1 - webhook_dispatcher.py
Ponte Wazuh -> Telegram para alertas de nivel alto (>= 10 por padrao).

O que faz:
  1. Le o arquivo de alertas do Wazuh (alerts.json) em tempo real.
  2. Filtra somente alertas que importam (level >= MIN_LEVEL).
  3. Evita spam do mesmo IP/regra por alguns minutos (cooldown).
  4. Monta uma mensagem PT-BR e envia pela API do Telegram.

Como rodar (Windows, com o Wazuh no ar):
  python alerting/webhook_dispatcher.py --test     # manda 1 alerta fake (prova o token)
  python alerting/webhook_dispatcher.py --follow   # fica ouvindo o Wazuh

Teste sem Telegram (nao envia, so mostra no terminal):
  python alerting/webhook_dispatcher.py --test --dry-run
  python alerting/webhook_dispatcher.py --follow --dry-run

Credenciais: alerting/.env (NAO vai pro git) ou variaveis de ambiente.
"""

import argparse
import datetime as dt
import getpass
import html
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
ENV_FILE = BASE_DIR / ".env"

DEFAULT_CONTAINER = "wazuh-manager"
DEFAULT_ALERTS_PATH = "/var/ossec/logs/alerts/alerts.json"


def carregar_env():
    """Le alerting/.env no formato CHAVE=VALOR. Variavel de ambiente tem prioridade."""
    if not ENV_FILE.exists():
        return
    for linha in ENV_FILE.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if not linha or linha.startswith("#") or "=" not in linha:
            continue
        chave, valor = linha.split("=", 1)
        chave = chave.strip()
        valor = valor.strip().strip('"').strip("'")
        os.environ.setdefault(chave, valor)


def configurar_console_utf8():
    """Windows usa cp1252 por padrão e quebra ao imprimir emoji no --dry-run."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def agora_iso():
    return dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def nivel_visual(level):
    if level >= 12:
        return "🔴 CRÍTICO"
    if level >= 10:
        return "🟠 ALTO"
    if level >= 8:
        return "🟡 MÉDIO"
    return "🟢 BAIXO"


def acao_sugerida(rule_id):
    """Sugestao curta de resposta. Entrevistador gosta de ver que voce sabe o 'e agora?'."""
    acoes = {
        "100101": "Bloquear o IP no firewall e revisar as tentativas SSH.",
        "100103": "Investigar o login externo: possível conta/host comprometido.",
        "100104": "Revisar os comandos executados e considerar isolar o host.",
    }
    return acoes.get(str(rule_id), "Triar o alerta e correlacionar com outros eventos.")


def montar_mensagem(alert):
    """Transforma o JSON do Wazuh em mensagem legivel. Usa HTML pra nao quebrar com _ ou *."""
    rule = alert.get("rule", {})
    data = alert.get("data", {}) or {}
    level = int(rule.get("level", 0) or 0)
    rule_id = rule.get("id", "?")
    descricao = rule.get("description", "Sem descrição")
    src_ip = data.get("srcip") or data.get("src_ip") or "desconhecido"
    usuario = data.get("user") or "N/A"
    timestamp = alert.get("timestamp", agora_iso())
    agente = (alert.get("agent") or {}).get("name", "wazuh-manager")

    e = html.escape
    return (
        "🚨 <b>ALERTA SOC — Purple Honeypot SIEM</b> 🚨\n\n"
        f"{nivel_visual(level)} <b>(nível {level})</b>\n"
        f"📌 <b>Regra:</b> <code>{e(str(rule_id))}</code> — {e(str(descricao))}\n"
        f"🌐 <b>Origem:</b> <code>{e(str(src_ip))}</code>\n"
        f"👤 <b>Usuário:</b> <code>{e(str(usuario))}</code>\n"
        f"🖥 <b>Agente:</b> {e(str(agente))}\n"
        f"🕒 <b>Horário:</b> {e(str(timestamp))}\n\n"
        f"✅ <b>Ação sugerida:</b>\n{e(acao_sugerida(rule_id))}"
    )


def telegram_configurado():
    return bool(os.getenv("TELEGRAM_BOT_TOKEN")) and bool(os.getenv("TELEGRAM_CHAT_ID"))


def obter_atualizacoes():
    """Chama getUpdates e devolve os chats que já falaram com o bot."""
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        print("[!] TELEGRAM_BOT_TOKEN não configurado no alerting/.env.")
        return []
    api_base = os.getenv("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
    url = f"{api_base}/bot{token}/getUpdates?limit=100&timeout=0"
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            corpo = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detalhe = exc.read().decode("utf-8", errors="ignore")[:300]
        print(f"[!] HTTP {exc.code} ao consultar o Telegram: {detalhe}")
        return []
    except urllib.error.URLError as exc:
        print(f"[!] Sem conexão com o Telegram: {exc.reason}")
        return []

    if not corpo.get("ok"):
        print(f"[!] Telegram recusou: {corpo.get('description', corpo)}")
        return []

    chats = {}
    for update in corpo.get("result", []):
        msg = update.get("message") or update.get("channel_post") or update.get("edited_message") or {}
        chat = msg.get("chat") or {}
        chat_id = chat.get("id")
        if chat_id is None:
            continue
        nome = chat.get("title") or chat.get("username") or chat.get("first_name") or "sem nome"
        chats[chat_id] = f"{chat.get('type', '?')} | {nome}"
    return list(chats.items())


def salvar_env(chave, valor):
    """Atualiza ou adiciona CHAVE=valor no alerting/.env, sem tocar no token."""
    if not ENV_FILE.exists():
        print(f"[!] {ENV_FILE} não existe. Copie de .env.example primeiro.")
        return False
    linhas = ENV_FILE.read_text(encoding="utf-8").splitlines()
    achou = False
    novas = []
    for linha in linhas:
        if linha.strip().startswith(f"{chave}="):
            novas.append(f"{chave}={valor}")
            achou = True
        else:
            novas.append(linha)
    if not achou:
        novas.append(f"{chave}={valor}")
    ENV_FILE.write_text("\n".join(novas) + "\n", encoding="utf-8")
    print(f"[+] {chave} salvo em {ENV_FILE.name}.")
    return True


def salvar_chat_id_no_env(chat_id):
    return salvar_env("TELEGRAM_CHAT_ID", chat_id)


def comando_chat_id(salvar=False):
    """Descobre o chat_id dos usuários que mandaram mensagem para o bot."""
    chats = obter_atualizacoes()
    if not chats:
        print("[!] Nenhuma conversa encontrada.")
        print("[*] Abra o seu bot no Telegram, mande /start e rode este comando de novo.")
        return
    print("\n[+] Conversas encontradas:")
    for chat_id, descricao in chats:
        print(f"    chat_id={chat_id}  ({descricao})")
    if salvar:
        if len(chats) == 1:
            salvar_chat_id_no_env(chats[0][0])
        else:
            print("[!] Há mais de uma conversa; rode sem --save e escolha o chat_id certo.")
    else:
        print("\n[*] Copie o chat_id para TELEGRAM_CHAT_ID no alerting/.env")
        print("[*] Ou rode de novo com --chat-id --save para salvar automaticamente.")


def enviar_telegram(texto, dry_run=False):
    """Envia a mensagem pela Bot API. Retorna True/False. Nao imprime o token."""
    if dry_run:
        print("\n----- DRY-RUN (não enviado) -----")
        print(texto)
        print("---------------------------------\n")
        return True

    if not telegram_configurado():
        print("[!] TELEGRAM_BOT_TOKEN e/ou TELEGRAM_CHAT_ID não configurados.")
        print("[*] Crie alerting/.env a partir de alerting/.env.example e preencha.")
        return False

    token = os.environ["TELEGRAM_BOT_TOKEN"]
    chat_id = os.environ["TELEGRAM_CHAT_ID"]
    api_base = os.getenv("TELEGRAM_API_BASE", "https://api.telegram.org").rstrip("/")
    url = f"{api_base}/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": texto,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")

    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            corpo = json.loads(resp.read().decode("utf-8"))
        if corpo.get("ok"):
            print("[+] Alerta enviado ao Telegram.")
            return True
        print(f"[!] Telegram recusou o envio: {corpo.get('description', corpo)}")
        return False
    except urllib.error.HTTPError as exc:
        detalhe = exc.read().decode("utf-8", errors="ignore")[:300]
        print(f"[!] HTTP {exc.code} no Telegram: {detalhe}")
        return False
    except urllib.error.URLError as exc:
        print(f"[!] Sem conexão com o Telegram: {exc.reason}")
        return False


def alerta_fake():
    """Alerta de exemplo para testar token, formatacao e celular."""
    return {
        "timestamp": agora_iso(),
        "rule": {
            "id": "100101",
            "level": 10,
            "description": "Honeypot SSH: possível brute-force, 5+ falhas do mesmo IP em 2 minutos.",
        },
        "agent": {"name": "wazuh-manager"},
        "data": {"srcip": "203.0.113.50", "user": "root"},
    }


class FiltroAntiSpam:
    """Evita mandar 20 mensagens iguais do mesmo IP em poucos minutos."""

    def __init__(self, cooldown_segundos=120):
        self.cooldown = cooldown_segundos
        self.vistos = {}

    def liberar(self, alert):
        rule_id = str((alert.get("rule") or {}).get("id", "?"))
        data = alert.get("data") or {}
        src_ip = str(data.get("srcip") or data.get("src_ip") or "?")
        chave = (rule_id, src_ip)
        agora = time.time()
        anterior = self.vistos.get(chave, 0)
        if agora - anterior < self.cooldown:
            return False
        self.vistos[chave] = agora
        return True


def processar_linha(linha, filtro, dry_run=False):
    """Recebe uma linha JSON do alerts.json e decide se envia."""
    linha = linha.strip()
    if not linha:
        return
    try:
        alert = json.loads(linha)
    except json.JSONDecodeError:
        return  # linha truncada (rotacao de log) ou lixo: ignora

    level = int((alert.get("rule") or {}).get("level", 0) or 0)
    min_level = int(os.getenv("MIN_LEVEL", "10"))
    if level < min_level:
        return

    if not filtro.liberar(alert):
        return

    rule_id = (alert.get("rule") or {}).get("id", "?")
    print(f"[ALERTA] nível {level} | regra {rule_id} | enviando...")
    enviar_telegram(montar_mensagem(alert), dry_run=dry_run)


def stream_arquivo_local(caminho, filtro, dry_run=False, from_start=False):
    """Le um alerts.json local que ja esta no disco (util p/ testar sem Docker)."""
    print(f"[*] Lendo arquivo local: {caminho}")
    with open(caminho, "r", encoding="utf-8", errors="ignore") as f:
        if not from_start:
            f.seek(0, os.SEEK_END)
        while True:
            linha = f.readline()
            if not linha:
                time.sleep(1)
                continue
            processar_linha(linha, filtro, dry_run)


def stream_docker(container, alerts_path, filtro, dry_run=False):
    """Executa `docker exec ... tail -F alerts.json` e processa cada linha."""
    cmd = ["docker", "exec", container, "tail", "-n", "0", "-F", alerts_path]
    print(f"[*] Ouvindo {container}:{alerts_path}")
    print("[*] Ctrl+C para parar.\n")
    while True:
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
            )
            for linha in proc.stdout:
                processar_linha(linha, filtro, dry_run)
            codigo = proc.wait()
            print(f"[!] tail terminou (código {codigo}). Tentando de novo em 5s...")
        except FileNotFoundError:
            print("[!] Comando 'docker' não encontrado no PATH.")
            return
        except KeyboardInterrupt:
            print("\n[*] Encerrando dispatcher...")
            return
        except Exception as exc:
            print(f"[!] Erro no stream: {exc}. Tentando de novo em 5s...")
        time.sleep(5)


def comando_setup():
    """Wizard: pede o token, salva, descobre chat_id e manda um teste."""
    print("=== Configuração do Telegram — Projeto 1 ===\n")
    print("1) No Telegram, fale com @BotFather -> /newbot (se ainda não fez).")
    print("2) Copie o token que ele devolveu.")
    print("3) Abra o seu bot e mande /start.\n")

    token_atual = os.getenv("TELEGRAM_BOT_TOKEN", "").strip()
    dica = " (Enter para manter o atual)" if token_atual else ""
    try:
        token = getpass.getpass(f"Cole o token do BotFather{dica}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[!] Cancelado.")
        return
    except Exception:
        token = input(f"Cole o token do BotFather{dica}: ").strip()

    if not token and token_atual:
        token = token_atual
    if not token:
        print("[!] Token vazio. Rode de novo e cole o token.")
        return
    if ":" not in token or len(token) < 30:
        print("[!] Isso não parece um token do Telegram (formato 123456:ABC...).")
        print("[*] Copie de novo a mensagem do BotFather, sem espaços.")
        return

    os.environ["TELEGRAM_BOT_TOKEN"] = token
    salvar_env("TELEGRAM_BOT_TOKEN", token)

    print("\n[*] Consultando o Telegram para descobrir seu chat_id...")
    chats = obter_atualizacoes()
    if not chats:
        print("[!] O bot ainda não recebeu mensagem sua.")
        print("[*] Abra o bot no Telegram, mande /start e rode: --setup de novo")
        return
    if len(chats) > 1:
        print("[!] Mais de uma conversa encontrada. Escolha uma e preencha o chat_id no .env:")
        for chat_id, descricao in chats:
            print(f"    chat_id={chat_id}  ({descricao})")
        return

    chat_id, descricao = chats[0]
    print(f"[+] Conversa encontrada: {chat_id} ({descricao})")
    salvar_env("TELEGRAM_CHAT_ID", chat_id)
    os.environ["TELEGRAM_CHAT_ID"] = str(chat_id)

    print("\n[*] Enviando mensagem de teste...")
    if enviar_telegram(montar_mensagem(alerta_fake())):
        print("[+] Pronto! Confira o Telegram no celular.")
        print("[*] Para alertas em tempo real: python alerting/webhook_dispatcher.py --follow")
    else:
        print("[!] O Telegram recusou. Confira o token e o chat_id no .env.")


def main():
    configurar_console_utf8()
    carregar_env()

    parser = argparse.ArgumentParser(description="Wazuh -> Telegram (Projeto 1)")
    modo = parser.add_mutually_exclusive_group(required=True)
    modo.add_argument("--setup", action="store_true", help="Wizard: salva token, descobre chat_id e testa")
    modo.add_argument("--test", action="store_true", help="Envia um alerta fake para testar o Telegram")
    modo.add_argument("--follow", action="store_true", help="Fica ouvindo os alertas do Wazuh")
    modo.add_argument("--chat-id", action="store_true", help="Descobre o chat_id de quem falou com o bot")
    parser.add_argument("--save", action="store_true", help="Com --chat-id, salva o chat_id no .env")
    parser.add_argument("--dry-run", action="store_true", help="Não envia: só mostra a mensagem no terminal")
    parser.add_argument("--file", help="Lê um alerts.json local em vez de usar docker exec")
    parser.add_argument("--from-start", action="store_true", help="Com --file, lê desde o começo (replay)")
    parser.add_argument("--container", default=os.getenv("WAZUH_CONTAINER", DEFAULT_CONTAINER))
    parser.add_argument("--alerts-path", default=os.getenv("ALERTS_PATH", DEFAULT_ALERTS_PATH))
    args = parser.parse_args()

    if args.setup:
        comando_setup()
        return

    if args.chat_id:
        comando_chat_id(salvar=args.save)
        return

    if args.test:
        if not args.dry_run and not telegram_configurado():
            print("[!] Faltam TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID.")
            print("[*] Copie alerting/.env.example para alerting/.env e preencha.")
            print("[*] Ou rode com --dry-run para ver a mensagem sem enviar.")
            sys.exit(1)
        enviar_telegram(montar_mensagem(alerta_fake()), dry_run=args.dry_run)
        return

    filtro = FiltroAntiSpam(cooldown_segundos=int(os.getenv("COOLDOWN_SECONDS", "120")))
    if not args.dry_run and not telegram_configurado():
        print("[!] Aviso: credenciais do Telegram ausentes; nada será enviado (use --dry-run).")

    if args.file:
        try:
            stream_arquivo_local(args.file, filtro, args.dry_run, args.from_start)
        except FileNotFoundError:
            print(f"[!] Arquivo não encontrado: {args.file}")
            sys.exit(1)
        except KeyboardInterrupt:
            print("\n[*] Encerrando dispatcher...")
    else:
        stream_docker(args.container, args.alerts_path, filtro, args.dry_run)


if __name__ == "__main__":
    main()
