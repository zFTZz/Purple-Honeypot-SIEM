# Demo 2-3 min — roteiro

Link do vídeo: (colar aqui quando subir no YouTube/Loom, ex: https://...)

## Antes de gravar (checklist)

- [ ] `docker ps` mostra `wazuh-manager`, `wazuh-indexer` e `wazuh-dashboard` como `Up`
- [ ] `alerting/.env` preenchido com token e chat_id
- [ ] `python alerting/webhook_dispatcher.py --test` já chegou no celular
- [ ] Honeypot SSH rodando em um terminal (PS1)
- [ ] Dispatcher rodando em outro terminal (PS2): `python alerting/webhook_dispatcher.py --follow`
- [ ] Celular/Telegram visível na gravação (ou espelhamento de tela)

## Roteiro

**0:00-0:20 — contexto e infra**
- Mostra `docker ps` (Wazuh up) e o honeypot ouvindo na 2222.
- Fala: "Honeypot SSH real em Python, Wazuh em Docker e regras custom."

**0:20-0:50 — ataque simulado**
- `ssh admin@localhost -p 2222`
- 1ª senha falha de propósito; 2ª entra.
- Roda `whoami`, `id`, `ls`, `cat id_rsa`.
- Fala: "A primeira falha gera o evento de autenticação; os comandos geram a sequência."

**0:50-1:20 — coleta**
- `Get-Content honeypot/logs/ssh.log -Tail 10`
- Mostra JSON com `type`, `src_ip`, `user`, `command`, `timestamp`.
- Fala: "Tudo em JSON, com IP e comando, pronto para o SIEM."

**1:20-1:50 — detecção**
- Abre o Wazuh/Kibana ou mostra `docker exec wazuh-manager tail -5 /var/ossec/logs/alerts/alerts.json`.
- Mostra as regras 100100/100101/100102/100104 (e 100103 se fizer login externo).
- Fala: "A regra 100101 correlaciona 5 falhas do mesmo IP; a 100104 correlaciona falha + recon."

**1:50-2:20 — alerta no celular**
- Mostra a notificação do Telegram chegando com regra, IP, usuário e ação sugerida.
- Fala: "O dispatcher filtra nível >= 10 e manda só o que importa; tem cooldown para não spammar."

**2:20-2:40 — fechamento**
- Volta no dashboard (top IPs/comandos) se estiver pronto.
- Fala: "Pipeline ponta a ponta: coletar -> detectar -> alertar. As limitações e próximos passos estão documentados no README."

## O que falar (30s)

"Construí um honeypot SSH/HTTP em Python que gera logs JSON. O Wazuh ingere esses logs via localfile, aplica cinco regras custom e grava os alertas. Um dispatcher em Python lê o alerts.json, filtra nível maior ou igual a 10 e manda para o Telegram. Provei o fluxo completo com brute-force, recon e login externo, e documentei as limitações e decisões de arquitetura."

## Erros comuns na gravação

- Esquecer de reiniciar o dispatcher depois de mudar o `.env`.
- Fazer só 1 tentativa de SSH e esperar brute-force (a 100101 precisa de 5+ falhas).
- Gravar o token do Telegram na tela. Deixe o `.env` fechado.
- Terminal pequeno: aumente a fonte antes de gravar.
