# Demo 2-3min — roteiro

Link do vídeo: (colar aqui quando subir no YouTube/Loom, ex: https://...)

## Roteiro (grava terminal + browser + Telegram lado a lado)
0:00-0:20 — mostra `docker ps` (wazuh up) + `python ssh_honeypot.py` ouvindo 2222
0:20-0:50 — ataca: `ssh admin@localhost -p 2222`, senha 123, roda `whoami`, `id`, `ls`, `cat id_rsa`
0:50-1:20 — mostra `Get-Content honeypot/logs/ssh.log` crescendo em tempo real
1:20-2:00 — mostra alerta no Wazuh/Kibana (regra bruteforce/sequence disparou)
2:00-2:30 — mostra alerta chegando no Telegram/Teams + dashboard (top IP, comandos)

## O que falar (30s)
"Construí honeypot SSH/HTTP que gera JSON, Filebeat manda pro Wazuh em Docker, regra custom detecta brute-force e sequência suspeita, webhook alerta no Telegram. Prova ponta a ponta coletar->detectar->alertar."
