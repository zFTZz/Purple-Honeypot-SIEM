# Purple Honeypot & SIEM Integration

Base de telemetria e detecção para **Purple Teaming**: honeypots em Python geram logs JSON, o Wazuh aplica regras custom e o alerta chega no Telegram. É o Projeto 1 do portfólio de Luiz Felipe (foco SOC/Blue Team).

> Snapshot de laboratório montado em Out/2026. Tudo descrito aqui foi executado neste repositório. Se o ambiente mudar, o comportamento pode mudar.

## Stack

- **Python** — honeypot SSH real (paramiko, porta 2222) + honeypot HTTP (porta 8080)
- **Docker Compose** — Wazuh 4.7.2 (manager + indexer + dashboard)
- **Wazuh localfile** — lê `honeypot/logs/*.log` em JSON e aplica as regras
- **Filebeat** — embutido no container do Wazuh, envia os alertas para o indexer (padrão oficial da stack); não é um container separado
- **Python** — `alerting/webhook_dispatcher.py` filtra nível >= 10 e envia ao Telegram
- **Kibana/Wazuh Dashboard** — visualização (dashboard ainda em construção)

## Arquitetura

```
Atacante -> Honeypot SSH/HTTP (Python) -> honeypot/logs/*.log (JSON lines)
              |
              v
     Wazuh manager (localfile JSON) -> regras custom
              |
              +--> alerts.json -> webhook_dispatcher.py -> Telegram (celular)
              |
              +--> Filebeat (dentro do manager) -> Wazuh Indexer -> Dashboard
```

Detalhes e decisões em `docs/architecture.md`. Roteiro do vídeo de 2-3 min em `docs/demo_video_link.md`.

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
2. Copie o **token** que ele devolver.
3. Abra uma conversa com o seu bot e mande `/start`.
4. Descubra o **chat_id** abrindo no navegador:
   `https://api.telegram.org/bot<SEU_TOKEN>/getUpdates`
   Procure `"chat":{"id":...}`.
5. Edite `alerting/.env` (não vai pro git) e preencha:

```env
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
```

Se `alerting/.env` não existir: `Copy-Item alerting/.env.example alerting/.env`.

### 5. Testar o alerta no celular

```powershell
python alerting/webhook_dispatcher.py --test
```

Tem que chegar uma mensagem no Telegram. Para só ver a mensagem no terminal, sem enviar:

```powershell
python alerting/webhook_dispatcher.py --test --dry-run
```

### 6. Deixar o alerta em tempo real

```powershell
python alerting/webhook_dispatcher.py --follow
```

Deixe rodando e, em outro terminal, faça 5+ tentativas de SSH com o mesmo IP. O dispatcher lê o `alerts.json` do container e envia só o que tem nível >= 10.

## Regras custom (5)

| Regra | Nível | O que detecta |
|---|---:|---|
| `100100` | 5 | uma falha de login SSH (base para correlação) |
| `100101` | 10 | brute-force: 5+ falhas do mesmo IP em 120s |
| `100102` | 8 | comando de reconhecimento (`id`, `whoami`, `uname`, `cat /etc/passwd`) |
| `100103` | 12 | login **bem-sucedido** vindo de fora das faixas internas (anomalia de origem) |
| `100104` | 12 | sequência: falha de login seguida de comandos de reconhecimento do mesmo IP |

Arquivo: `siem/custom_rules/bruteforce_custom.xml`.

Decisões que valem entrevista:
- `<same_source_ip />` em vez de `<same_srcip />`: a segunda não dispara com log JSON no Wazuh 4.7.2 (testado).
- `<field type="pcre2">` com `^...$`: o match padrão casa por substring (`ssh.login` casaria `ssh.login_failed`).
- Só uma regra dispara por evento; por isso a geo (100103) ficou no evento de login com sucesso, sem competir com a 100100.
- O dispatcher filtra por nível e tem cooldown para não mandar 20 mensagens do mesmo ataque.

## Estrutura

```
Purple-Honeypot-SIEM/
├── honeypot/ssh_honeypot.py, http_honeypot.py, logs/
├── siem/docker-compose.yml, filebeat.yml (referência), custom_rules/bruteforce_custom.xml
├── alerting/webhook_dispatcher.py, .env.example, teams_alert.ps1
├── deploy/setup.sh
└── docs/architecture.md, demo_video_link.md
```

## Status do projeto

Concluído e testado na mão: honeypot SSH/HTTP, ingestão no Wazuh, 5 regras custom, brute-force/geo/sequência disparando no `alerts.json`, dispatcher Wazuh -> Telegram (testado contra um mock local).

Pendente: token real do Telegram (teste no celular), dashboard no Kibana, `setup.sh` de instalação, honeypot FTP (opcional), vídeo de 2-3 min e simulação de entrevista.

## O que NÃO fazer

- Não commitar `alerting/.env` nem `honeypot/host.key` (já estão no `.gitignore`).
- Não prometer "Filebeat lê os logs crus": nesse projeto o Wazuh lê os arquivos via `localfile`; o Filebeat que existe na stack é o oficial do Wazuh, que envia os **alertas** para o indexer.
- Não usar as senhas reais em lugar nenhum: o honeypot aceita qualquer senha de propósito, só para gerar telemetria.
