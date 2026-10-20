# Purple Honeypot & SIEM Integration

Base de telemetria e detecção para **Purple Teaming**: honeypots em Python geram logs JSON, o Wazuh aplica regras custom e o alerta chega no Telegram. É o Projeto 1 do portfólio de Luiz Felipe (foco SOC/Blue Team).

> Snapshot de laboratório montado em Out/2026. Tudo descrito aqui foi executado neste repositório. Se o ambiente mudar, o comportamento pode mudar.

## Stack

- **Python** — honeypot SSH real (paramiko, porta 2222) + honeypot HTTP (porta 8080) + honeypot FTP (porta 2121)
- **Docker Compose** — Wazuh 4.7.2 (manager + indexer + dashboard)
- **Wazuh localfile** — lê `honeypot/logs/*.log` em JSON e aplica as regras
- **Filebeat** — embutido no container do Wazuh, envia os alertas para o indexer (padrão oficial da stack); não é um container separado
- **Python** — `alerting/webhook_dispatcher.py` filtra nível >= 10 e envia ao Telegram
- **Kibana/Wazuh Dashboard** — visualização com 5 painéis (regras, timeline, IPs, comandos e alertas recentes)

## Arquitetura

```
Atacante -> Honeypot SSH/HTTP/FTP (Python) -> honeypot/logs/*.log (JSON lines)
              |
              v
     Wazuh manager (localfile JSON) -> regras custom
              |
              +--> alerts.json -> webhook_dispatcher.py -> Telegram (celular)
              |
              +--> Filebeat (dentro do manager) -> Wazuh Indexer -> Dashboard
```

Detalhes e decisões em `docs/architecture.md`. Relatório técnico completo, com bugs e soluções, em `docs/RELATORIO.md`. Roteiro do vídeo de 2-3 min em `docs/demo_video_link.md`.

## Como rodar

### 1. Subir o Wazuh

```powershell
cd C:\GIT-GITHUB\Purple-Honeypot-SIEM
docker compose -f siem/docker-compose.yml up -d
docker ps --filter name=wazuh
```

Dashboard: `https://localhost:5601` (admin/admin). Manager: `localhost:55000`.

### 2. Subir o honeypot SSH

```powershell
python honeypot/ssh_honeypot.py
```

Deixe esse terminal aberto (PS1). Não digite nele; `Ctrl+C` para parar.

### 3. Testar o honeypot (outro terminal)

```powershell
ssh admin@localhost -p 2222
# 1a senha sempre falha de propósito (gera ssh.login_failed)
# 2a senha entra (qualquer uma)
whoami
id
ls
cat id_rsa
exit
```

Ver o log:

```powershell
Get-Content honeypot/logs/ssh.log -Tail 10
```

### 4. Configurar o Telegram (1 vez)

1. No Telegram, fale com **@BotFather** -> `/newbot` -> escolha nome e usuário.
2. Copie o **token** que ele devolver e mande `/start` para o seu bot.
3. Rode o wizard e cole o token quando ele pedir (o token não aparece na tela):

```powershell
python alerting/webhook_dispatcher.py --setup
```

O wizard salva o token em `alerting/.env`, descobre o `chat_id`, salva e já
manda uma mensagem de teste. Se `alerting/.env` não existir:
`Copy-Item alerting/.env.example alerting/.env`.

### 5. Testar o alerta no celular de novo (opcional)

```powershell
python alerting/webhook_dispatcher.py --test
```

Para só ver a mensagem no terminal, sem enviar:

```powershell
python alerting/webhook_dispatcher.py --test --dry-run
```

### 6. Deixar o alerta em tempo real

```powershell
python alerting/webhook_dispatcher.py --follow
```

Deixe rodando e, em outro terminal, faça 6+ tentativas de SSH com o mesmo IP
(ver explicação do lote na seção de regras). O dispatcher lê o `alerts.json` do
container e envia só o que tem nível >= 10.

### 7. Simular o ataque completo (para o vídeo)

Com o honeypot rodando em um terminal e o dispatcher em outro:

```powershell
python honeypot/simulate_attack.py
```

O simulador fala SSH de verdade com o honeypot: erra 6 senhas, entra na
tentativa seguinte e executa `whoami`. Isso gera `ssh.login_failed`,
`ssh.login` e `ssh.command` no `ssh.log`, e as regras 100101 + 100104 disparam.
Ele é só uma ferramenta de laboratório; o honeypot continua sendo o alvo.

### 8. Honeypots HTTP e FTP

```powershell
# Terminal extra: HTTP na 8080
python honeypot/http_honeypot.py
# abra http://localhost:8080/.env e http://localhost:8080/admin

# Terminal extra: FTP na 2121 (21 exigiria admin no Windows)
python honeypot/ftp_honeypot.py
# ftp admin@localhost -p 2121  (1a senha falha, 2a entra; LIST/RETR mostram isca)
```

O FTP segue a mesma lógica do SSH: a primeira senha de cada conexão falha de
propósito para alimentar a regra de brute-force (100110). Log em
`honeypot/logs/ftp.log`.

## Regras custom (11)

| Regra | Nível | O que detecta |
|---|---:|---|
| `100100` | 5 | uma falha de login SSH (base para correlação) |
| `100101` | 10 | brute-force SSH: 5+ falhas do mesmo IP em 120s |
| `100102` | 8 | comando de reconhecimento SSH (`id`, `whoami`, `uname`, `cat /etc/passwd`) |
| `100103` | 12 | login **bem-sucedido** vindo de fora das faixas internas (anomalia de origem) |
| `100104` | 12 | sequência SSH: falha de login seguida de comando de reconhecimento do mesmo IP |
| `100105` | 8 | HTTP com User-Agent de ferramenta de scan (sqlmap, nikto, nmap, ffuf...) |
| `100106` | 8 | HTTP em caminho sensível (isca: `/.env`, `/admin`...) ou path traversal |
| `100107` | 6 | HTTP POST recebido (todo POST em honeypot é suspeito) |
| `100108` | 10 | scan HTTP: 10+ acessos a caminhos sensíveis do mesmo IP em 60s |
| `100109` | 5 | falha de login FTP (base para correlação) |
| `100110` | 10 | brute-force FTP: 5+ falhas do mesmo IP em 120s |

Arquivo: `siem/custom_rules/bruteforce_custom.xml`.

Decisões que valem entrevista:
- `<same_source_ip />` em vez de `<same_srcip />`: a segunda não dispara com log JSON no Wazuh 4.7.2 (testado).
- `<field type="pcre2">` com `^...$`: o match padrão casa por substring (`ssh.login` casaria `ssh.login_failed`).
- Só uma regra dispara por evento; por isso a geo (100103) ficou no evento de login com sucesso, sem competir com a 100100.
- A 100104 **não usa `frequency`**: uma segunda regra de frequency apontando para a 100100 consumia os eventos e impedia a 100101 de disparar. Com `if_sid` (comando atual) + `if_matched_sid` (falha anterior), ela dispara no primeiro comando de recon.
- No teste manual, use **6 falhas**: o logcollector pode agrupar eventos em lote e a 5ª às vezes é avaliada antes de entrar na janela da 100101. A 6ª garante o disparo.
- O dispatcher filtra por nível e tem cooldown para não mandar 20 mensagens do mesmo ataque.

## Dashboard

- URL: **https://localhost:5601**
- Login do laboratório: **admin / admin**
- Dashboard pronto: **Purple Honeypot SIEM** (menu Dashboards)
- O script `siem/create_dashboard.py` recria/atualiza o index pattern e os 5 painéis:
  alertas por regra, alertas no tempo, top IPs, comandos executados e alertas recentes.

```powershell
python siem/create_dashboard.py
```

O dashboard lê o índice `wazuh-alerts-*`, alimentado pelo Filebeat que já vem
dentro do container do manager. Se o dashboard abrir com **503** ou
"Security not initialized", rode uma vez:

```powershell
docker exec -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk wazuh-indexer bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh -cd /usr/share/wazuh-indexer/opensearch-security -icl -nhnv -cacert /usr/share/wazuh-indexer/certs/root-ca.pem -cert /usr/share/wazuh-indexer/certs/admin.pem -key /usr/share/wazuh-indexer/certs/admin-key.pem
```

## Estrutura

```
Purple-Honeypot-SIEM/
├── honeypot/ssh_honeypot.py, http_honeypot.py, ftp_honeypot.py, simulate_attack.py, logs/
├── siem/docker-compose.yml, filebeat.yml (referência), custom_rules/bruteforce_custom.xml
├── siem/create_dashboard.py
├── alerting/webhook_dispatcher.py, .env.example, teams_alert.ps1
├── deploy/setup.sh
└── docs/architecture.md, RELATORIO.md, demo_video_link.md
```

## Status do projeto

Concluído e testado na mão: honeypots SSH/HTTP/FTP, simulador de ataque SSH, ingestão no Wazuh (3 protocolos), 11 regras custom (SSH/HTTP/FTP), brute-force/sequência/geo/scan disparando no `alerts.json`, dispatcher Wazuh -> Telegram com **mensagens reais no celular** (100101 e 100104), e dashboard `Purple Honeypot SIEM` com 5 painéis.

Pendente: vídeo de 2-3 min com o simulador e simulação de entrevista.

## O que NÃO fazer

- Não commitar `alerting/.env` nem `honeypot/host.key` (já estão no `.gitignore`).
- Não prometer "Filebeat lê os logs crus": nesse projeto o Wazuh lê os arquivos via `localfile`; o Filebeat que existe na stack é o oficial do Wazuh, que envia os **alertas** para o indexer.
- Não usar as senhas reais em lugar nenhum: o honeypot aceita qualquer senha de propósito, só para gerar telemetria.
