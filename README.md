# Purple Honeypot & SIEM Integration

Base de telemetria e detecção para **Purple Teaming**. Honeypots multi-protocolo em Python geram logs JSON, Filebeat envia para Wazuh em Docker, regras custom disparam alerta no Telegram/Teams e dashboard no Kibana mostra quem atacou.

> Snapshot: lab montado em Out/2026 por Luiz Felipe. Tudo aqui foi testado entre Out-Nov/2026 nesse repo. Se o ambiente mudar, o comportamento pode mudar.

## Stack
- **Python** — honeypot SSH (paramiko, porta 2222) + HTTP (porta 8080)
- **Docker Compose** — Wazuh + Kibana
- **Filebeat** — lê `honeypot/logs/*.log` e manda pro Wazuh
- **PowerShell/Python** — webhook Telegram/Teams

## Arquitetura
```
Atacante -> Honeypot SSH/HTTP (Python) -> logs/*.log em JSON
  -> Filebeat -> Wazuh (regras custom) -> webhook Telegram/Teams
  -> Kibana dashboard (top atacantes, timeline, comandos)
```
Detalhe com diagrama em `docs/architecture.md`. Roteiro do vídeo 2-3min em `docs/demo_video_link.md`.

## Como rodar (MVP)
```powershell
# 1. honeypot SSH (terminal 1, deixa aberto)
python honeypot/ssh_honeypot.py
# 2. teste (terminal 2)
ssh admin@localhost -p 2222
# senha qualquer, tenta: whoami, id, ls, cat id_rsa, exit
# 3. ver log gerado
Get-Content honeypot/logs/ssh.log

# HTTP
python honeypot/http_honeypot.py
# abre http://localhost:8080/.env
```

## Estrutura
```
purple-honeypot-siem/
├── honeypot/ssh_honeypot.py, http_honeypot.py, logs/
├── siem/docker-compose.yml, filebeat.yml, custom_rules/*.xml
├── alerting/webhook_dispatcher.py, teams_alert.ps1
├── deploy/setup.sh
└── docs/architecture.md, demo_video_link.md
```

## Regras custom (mínimo 3)
1. `bruteforce_custom.xml` — N logins falhos / X min no mesmo IP
2. `suspicious_sequence.xml` — login falho -> comando `whoami/id/uname` em sequência
3. `geo_anomaly.xml` — IP fora do perfil BR/MG

## O que provar no vídeo
Ataque simulado -> `ssh.log` crescendo -> regra dispara no Wazuh -> alerta chega no Telegram. É isso que o gestor de SOC quer ver.
