# Relatório Técnico — Purple Honeypot SIEM

**Projeto:** Projeto 1 — Honeypot Interativo + SIEM & Dashboards  
**Autor:** Luiz Felipe — portfólio SOC/Blue Team  
**Data:** 19/10/2026 (horário local; os logs do laboratório usam UTC)  
**Status:** MVP funcional de laboratório. Vídeo, entrevista simulada e endurecimento para produção ainda pendentes.  
**Repositório local:** `C:\GIT-GITHUB\Purple-Honeypot-SIEM`  
**Stack principal:** Python, Paramiko, Docker Compose, Wazuh 4.7.2, Wazuh Indexer, Wazuh Dashboard/OpenSearch Dashboards, Filebeat, Telegram Bot API.

> Este é um relatório de laboratório. Tokens, chat IDs e conteúdos de `alerting/.env` não são reproduzidos aqui. As credenciais `admin/admin` e os usuários padrão do Wazuh são intencionais neste ambiente isolado e **não devem ser usados em produção**.

---

## Sumário

1. [Resumo executivo](#1-resumo-executivo)
2. [Objetivo e escopo](#2-objetivo-e-escopo)
3. [Arquitetura e fluxo de dados](#3-arquitetura-e-fluxo-de-dados)
4. [Componentes implementados](#4-componentes-implementados)
5. [Regras de detecção](#5-regras-de-detecção)
6. [Decisões de projeto](#6-decisões-de-projeto)
7. [Bugs, hipóteses e soluções](#7-bugs-hipóteses-e-soluções)
8. [Testes e evidências](#8-testes-e-evidências)
9. [Segurança, riscos e limitações](#9-segurança-riscos-e-limitações)
10. [Preparação para entrevista](#10-preparação-para-entrevista)
11. [Pendências e próximos passos](#11-pendências-e-próximos-passos)
12. [Como reproduzir](#12-como-reproduzir)
13. [Apêndices](#13-apêndices)

---

## 1. Resumo executivo

O projeto entrega um pipeline funcional de **coleta, detecção, alerta e visualização** para um honeypot de laboratório:

1. Um atacante — ou o simulador `honeypot/simulate_attack.py` — conecta no honeypot SSH (`localhost:2222`) ou no honeypot HTTP (`localhost:8080`).
2. O honeypot grava um evento JSON por linha em `honeypot/logs/ssh.log` ou `http.log`, com IP, usuário, senha/comando e timestamp UTC.
3. O Wazuh Manager lê esses arquivos via `localfile` com `log_format=json`.
4. Cinco regras customizadas detectam falha isolada, brute-force, reconhecimento, login externo e sequência falha → reconhecimento.
5. O alerta é gravado em `/var/ossec/logs/alerts/alerts.json`.
6. O dispatcher lê esse arquivo via `docker exec`, filtra nível ≥ 10, aplica cooldown e envia uma mensagem HTML para o Telegram.
7. O Filebeat **embutido no container do manager** envia os alertas ao Wazuh Indexer; o Wazuh Dashboard mostra cinco painéis: alertas por regra, timeline, top IPs, comandos executados e alertas recentes.

**Evidência mais importante:** em teste real, seis falhas de senha seguidas de um comando `whoami` geraram os alertas `100101` (nível 10) e `100104` (nível 12), e as duas mensagens chegaram ao Telegram. O dashboard foi criado via API e responde em `https://localhost:5601`.

**Em uma frase para entrevista:** “Eu construí um honeypot SSH/HTTP que gera telemetria JSON, correlaciono os eventos no Wazuh com cinco regras custom e levo o alerta ao Telegram, com um dashboard para triagem.”

---

## 2. Objetivo e escopo

### 2.1 Objetivo

Provar, ponta a ponta, a capacidade de:

- **coletar** telemetria de um alvo falso;
- **detectar** comportamento suspeito com regras próprias, sem depender só do ruleset padrão;
- **alertar** rapidamente uma pessoa;
- **visualizar** os eventos para triagem;
- **documentar** decisões e limitações com maturidade de laboratório.

É um MVP para estágio em SOC/Blue Team, não um produto de produção.

### 2.2 Requisitos da especificação × entrega

| Requisito | O que foi entregue | Status |
|---|---|---|
| Honeypot SSH | `ssh_honeypot.py`, SSH real com Paramiko na porta 2222 | ✅ |
| Honeypot HTTP | `http_honeypot.py`, iscas e captura de User-Agent na porta 8080 | ✅ |
| Honeypot FTP | Não implementado | ⏳ opcional |
| Honeypots multi-protocolo | SSH + HTTP (dois protocolos) | ✅ |
| Captura de IP, usuário, credenciais, comandos e User-Agent | SSH captura IP/usuário/senha/comando; HTTP captura IP/método/path/User-Agent/body | ✅ |
| Logs em JSON | Um JSON por linha, timestamp UTC | ✅ |
| Filebeat → Wazuh | Filebeat já vem dentro do manager e envia `alerts.json` ao indexer; os logs do honeypot entram por `localfile` | ✅ com ressalva de arquitetura |
| Mínimo de 3 regras custom | 5 regras (`100100`–`100104`) | ✅ |
| Brute-force com threshold próprio | `100101`: 5 falhas do mesmo IP em 120 s | ✅ |
| Sequência falha → reconhecimento | `100104`: falha + comando de recon do mesmo IP | ✅ |
| Geolocalização anômala | `100103`: login bem-sucedido de IP fora das faixas internas (heurística CIDR, **não** GeoIP real) | ✅ parcial |
| Dashboard com top atacantes, timeline e comandos | 5 painéis no Wazuh Dashboard | ✅ |
| Alerta Telegram/Teams | Telegram real; `teams_alert.ps1` como fallback | ✅ |
| `setup.sh` | Script idempotente de subida, segurança, localfile e dashboard | ✅ |
| Vídeo de 2–3 min | Roteiro pronto em `docs/demo_video_link.md` | ⏳ |
| Entrevista simulada | Ainda não realizada | ⏳ |

### 2.3 O que este projeto não é

- Não é um honeypot de alta interação: o shell é simulado.
- Não é um SIEM de produção: é um nó Wazuh de laboratório.
- Não faz GeoIP real; a regra de “geolocalização” é uma **anomalia de origem** baseada em faixas privadas.
- Não possui regras HTTP específicas ainda: os logs HTTP são coletados, mas as cinco regras atuais são de SSH.
- Não possui HA, retenção de longo prazo, TLS com certificado público nem RBAC endurecido.

---

## 3. Arquitetura e fluxo de dados

### 3.1 Diagrama real

```text
Atacante / scanner / simulador
        |
        +---- SSH :2222 ----------------------+
        |                                     |
        +---- HTTP :8080 ---------------------+
                                              |
                                              v
                         honeypot/logs/ssh.log e http.log
                         (JSON lines, timestamp UTC)
                                              |
                                              v
                         Wazuh Manager (container)
                         localfile + log_format=json
                                              |
                                              v
                         analysisd + regras custom
                         100100 base
                         100101 brute-force
                         100102 recon
                         100103 login externo
                         100104 sequência
                                              |
                    +-------------------------+-------------------------+
                    |                                                   |
                    v                                                   v
        /var/ossec/logs/alerts/alerts.json              Filebeat embutido no manager
                    |                                                   |
                    v                                                   v
        webhook_dispatcher.py                              Wazuh Indexer :9200
        nível >= 10 + cooldown 120 s                                  |
                    |                                                   v
                    v                                      Wazuh Dashboard :5601
              Telegram (celular)                          5 painéis do honeypot
```

### 3.2 Portas e caminhos

| Elemento | Endereço/caminho |
|---|---|
| Honeypot SSH | `0.0.0.0:2222` |
| Honeypot HTTP | `0.0.0.0:8080` |
| Wazuh Manager API | `https://localhost:55000` |
| Wazuh Indexer | `https://localhost:9200` |
| Wazuh Dashboard | `https://localhost:5601` |
| Logs do honeypot (host) | `honeypot/logs/ssh.log`, `honeypot/logs/http.log` |
| Logs do honeypot (manager) | `/var/log/honeypot/ssh.log`, `/var/log/honeypot/http.log` |
| Alertas do Wazuh | `/var/ossec/logs/alerts/alerts.json` |
| Regras custom | `siem/custom_rules/bruteforce_custom.xml` |
| Índice do dashboard | `wazuh-alerts-*` |

### 3.3 Ponto importante: onde está o Filebeat?

A especificação fala “Filebeat → Wazuh”. Neste laboratório, **o Filebeat não é um container separado**: a imagem oficial do Wazuh Manager 4.7.2 já executa o Filebeat 7.10.2 internamente e envia os alertas do manager para o indexer. Os logs do honeypot entram no manager por `localfile`, não pelo Filebeat.

O arquivo `siem/filebeat.yml` existe como **referência documental** do que o Filebeat interno faz. Essa decisão reduz containers e pontos de falha, mas cria um acoplamento maior com a imagem do manager. Em uma arquitetura clássica de ELK, o Filebeat seria um agente separado lendo os logs e enviando ao Elasticsearch/OpenSearch.

---

## 4. Componentes implementados

### 4.1 Honeypot SSH — `honeypot/ssh_honeypot.py`

- Usa **Paramiko** para fazer um handshake SSH real, compatível com o cliente OpenSSH.
- Escuta em `0.0.0.0:2222`.
- A **primeira senha de cada conexão sempre falha**; da segunda em diante, qualquer senha é aceita. Isso imita um servidor real e garante eventos de falha para a regra de brute-force.
- Cada conexão é tratada em uma thread.
- O shell é falso: responde a `whoami`, `id`, `hostname`, `uname`, `ls`, `pwd`, `cat id_rsa`, `cat config.env` e `cat app.py`, com dados fictícios.
- Registra `ssh.login_failed`, `ssh.login` e `ssh.command`.
- O campo `src_ip` é duplicado como `srcip` para compatibilidade com as regras.
- O timestamp é gerado em UTC no formato ISO 8601 com `Z`.
- A chave do servidor é gerada uma vez em `honeypot/host.key` e não deve ser commitada.
- O `socket.settimeout(1.0)` foi usado para o `Ctrl+C` funcionar no Windows.

### 4.2 Honeypot HTTP — `honeypot/http_honeypot.py`

- Usa `http.server` na porta 8080.
- Responde a `GET` e `POST`.
- Registra `http.request` com IP, método, path, User-Agent, body (limitado a 2000 caracteres) e flag `suspicious`.
- Iscas: `/.env`, `/robots.txt`, `/admin`, `/login`, `/.git`, `/config.php`, `/backup`.
- Devolve conteúdo falso tentador, como `DB_PASSWORD` e `AWS_KEY` fictícios.
- O `POST` é sempre marcado como suspeito.
- Ainda não há regra custom específica para HTTP; os eventos são coletados e ficam disponíveis no índice.

### 4.3 Simulador — `honeypot/simulate_attack.py`

- Não é o honeypot; é um **cliente SSH de laboratório** que ataca o honeypot.
- Abre seis conexões e erra a senha em cada uma para gerar seis `ssh.login_failed`.
- Depois abre uma conexão, erra a primeira senha e acerta a segunda, gerando `ssh.login`.
- Executa um comando de reconhecimento (padrão `whoami`), gerando `ssh.command`.
- É útil para o vídeo e para testes reproduzíveis, sem digitar senha seis vezes na mão.
- Aceita `--host`, `--port`, `--user`, `--attempts`, `--command` e `--delay`.

### 4.4 Wazuh — `siem/docker-compose.yml`

- Wazuh Manager 4.7.2, Wazuh Indexer 4.7.2 e Wazuh Dashboard 4.7.2.
- Manager expõe 1514/1515 e 55000; indexer 9200; dashboard 5601.
- O dashboard usa a porta 5601 porque 443 e 8443 já estavam ocupadas no host.
- O indexer usa a segurança do OpenSearch; o índice `.opendistro_security` é inicializado com `securityadmin.sh`.
- O serviço do indexer tem o alias de rede `wazuh.indexer` (com ponto), porque o dashboard oficial procura esse hostname.
- O volume `siem_wazuh-manager-etc` guarda o `ossec.conf` e sobrevive a reinícios.
- O `ossec.conf` recebe os blocos de `localfile` para os logs do honeypot.

### 4.5 Regras — `siem/custom_rules/bruteforce_custom.xml`

Cinco regras na faixa `100100+`, sem sobrescrever regras nativas do Wazuh. Detalhes na seção 5.

### 4.6 Dispatcher — `alerting/webhook_dispatcher.py`

- Lê o `alerts.json` via `docker exec ... tail -F` ou de um arquivo local.
- Filtra `rule.level >= 10` (configurável em `MIN_LEVEL`).
- Cooldown de 120 s por combinação de regra + IP (`COOLDOWN_SECONDS`).
- Monta mensagem em HTML com regra, nível, IP, usuário, agente, horário e ação sugerida.
- Faz escape de HTML para não quebrar com `_`, `*` ou caracteres especiais.
- Comandos:
  - `--setup`: wizard que pede o token sem exibir, salva no `.env`, descobre o `chat_id` e envia um teste.
  - `--test`: envia um alerta fake.
  - `--follow`: fica ouvindo o Wazuh em tempo real.
  - `--file`: lê um arquivo local.
  - `--from-start`: com `--file`, lê desde o começo.
  - `--dry-run`: não envia, só mostra no terminal.
  - `--chat-id` e `--save`: descoberta e gravação do chat ID.
- O token fica em `alerting/.env`, que é ignorado pelo Git.

### 4.7 Dashboard — `siem/create_dashboard.py`

- Script idempotente que usa a API do Wazuh Dashboard/OpenSearch Dashboards.
- Cria o index pattern `wazuh-alerts-*` com campo de tempo `@timestamp`.
- Cria/atualiza cinco painéis:
  1. **Alertas por regra** — pizza/donut com `rule.id`.
  2. **Alertas ao longo do tempo** — linha com `date_histogram` em `@timestamp`, separada por `rule.id`.
  3. **Top IPs** — tabela com `data.srcip`.
  4. **Comandos executados** — tag cloud com `data.command`.
  5. **Alertas recentes** — saved search com `@timestamp`, `rule.id`, `rule.level`, `rule.description`, `data.srcip`, `data.user` e `data.command`.
- Usa referências corretas entre dashboard, visualizações e index pattern.
- É idempotente: procura pelo título e atualiza em vez de duplicar.

### 4.8 Setup — `deploy/setup.sh`

- Verifica Docker, Docker Compose e `curl`.
- Cria `honeypot/logs/ssh.log` e `http.log`.
- Cria `alerting/.env` a partir do exemplo se não existir.
- Sobe a stack.
- Espera o indexer responder.
- Se o índice de segurança não existir, roda `securityadmin.sh`.
- Adiciona os blocos `localfile` no `ossec.conf` somente se ainda não estiverem presentes.
- Valida o `ossec.conf` com `wazuh-analysisd -t`.
- Espera o dashboard e executa `siem/create_dashboard.py`.
- É idempotente: rodar duas vezes não duplica configuração.

### 4.9 Fallback Teams — `alerting/teams_alert.ps1`

Script PowerShell opcional para enviar alerta a um webhook do Teams. O Telegram foi escolhido para o MVP por ser mais simples de testar no celular; o Teams fica como alternativa corporativa.

---

## 5. Regras de detecção

Arquivo: `siem/custom_rules/bruteforce_custom.xml`.

| ID | Nível | Condição | Objetivo | Observações |
|---|---:|---|---|---|
| `100100` | 5 | `type` exatamente `ssh.login_failed` | Evento base de falha | Serve de âncora para as correlações |
| `100101` | 10 | 5+ eventos `100100` do mesmo IP em 120 s | Brute-force SSH | `same_source_ip`; sem `ignore`; anti-spam no dispatcher |
| `100102` | 8 | `type=ssh.command` e comando de recon | Reconhecimento pós-acesso | `id`, `whoami`, `uname`, `cat /etc/passwd` etc. |
| `100103` | 12 | `type=ssh.login` e IP externo | Anomalia de origem | Não é GeoIP real; usa faixas privadas; `ignore=300` |
| `100104` | 12 | `100102` + falha `100100` do mesmo IP em 300 s | Sequência falha → recon | Sem `frequency`; dispara no primeiro comando após a falha |

### 5.1 Regras principais em resumo

```xml
<!-- 100100: falha isolada -->
<rule id="100100" level="5">
  <field name="type" type="pcre2">^ssh\.login_failed$</field>
  <description>Honeypot SSH: tentativa de login falhou.</description>
</rule>

<!-- 100101: brute-force -->
<rule id="100101" level="10" frequency="5" timeframe="120">
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Honeypot SSH: possível brute-force, 5+ falhas do mesmo IP em 2 minutos.</description>
</rule>

<!-- 100104: sequência -->
<rule id="100104" level="12" timeframe="300">
  <if_sid>100102</if_sid>
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Honeypot SSH: sequência suspeita — falha de login seguida de comando de reconhecimento pelo mesmo IP.</description>
</rule>
```

### 5.2 Por que `same_source_ip` e não `same_srcip`

Com logs JSON, o campo do IP fica em `data.srcip` (e o decoder expõe `srcip`). No Wazuh 4.7.2 testado, `<same_srcip />` não disparou de forma confiável nesse formato; `<same_source_ip />` funcionou. Essa foi uma correção empírica, validada no pipeline real.

### 5.3 Por que `pcre2` ancorado

O match padrão de `<field>` no Wazuh é por **substring**. Uma regra com `ssh.login` também casaria `ssh.login_failed`. Por isso todos os campos de texto exato usam:

```xml
<field name="type" type="pcre2">^ssh\.login_failed$</field>
```

### 5.4 Por que a geo ficou no login bem-sucedido

O Wazuh gera **um alerta por evento**. Se a regra de anomalia de origem estivesse no evento de falha, ela poderia “engolir” a `100100` e impedir a correlação de brute-force. A `100103` foi colocada no evento `ssh.login` (sucesso), o que também faz sentido de negócio: login externo bem-sucedido é mais crítico que uma falha isolada.

A regra usa uma regex negativa para IPs privados:

```text
^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.|127\.)
```

Isso é uma **heurística de origem**, não geolocalização. Um IP público legítimo também dispararia. Em produção, o próximo passo seria enriquecer com MaxMind/ipinfo e listas de confiança.

### 5.5 Por que a `100104` não usa `frequency`

A `100104` foi originalmente implementada com `frequency="2"` e `if_matched_sid 100100`. O comportamento observado foi:

- a `100101` funcionava no `wazuh-logtest`;
- no pipeline real, muitas vezes só a `100100` disparava;
- ao desativar temporariamente a `100104`, a `100101` voltou a disparar;
- ao reativar a versão com `frequency`, a `100101` voltou a falhar.

A conclusão foi que uma **segunda regra de frequency apontando para a mesma `100100` consumia/alterava os eventos** usados pela `100101`. A solução foi remover `frequency` da `100104` e usar:

- `if_sid 100102`: o evento atual é o comando de recon;
- `if_matched_sid 100100`: existe uma falha anterior do mesmo IP;
- `same_source_ip`: a falha e o comando são do mesmo atacante;
- `timeframe="300"`: a janela é de 5 minutos.

Com isso, a `100104` dispara no **primeiro** comando de recon após uma falha, sem competir com a `100101`.

### 5.6 Por que usar 6 tentativas no teste

O `logcollector` pode agrupar linhas em lote. Em alguns testes, a 5ª falha era avaliada antes de entrar na janela de correlação e a `100101` não disparava. A sexta tentativa garantia o gatilho. Em produção, um ataque real faz muito mais de cinco tentativas, então isso é uma questão de **teste reproduzível**, não uma limitação prática séria.

---

## 6. Decisões de projeto

| # | Decisão | Alternativas | Motivo | Trade-off |
|---:|---|---|---|---|
| 1 | SSH real com Paramiko | Banner fake em socket | Compatível com cliente OpenSSH, captura comandos e autenticação de verdade | Mais complexo e mais dependências |
| 2 | Logs em JSON lines | Texto livre, syslog | Fácil de ingerir, campos estruturados, um evento por linha | Exige decoder/mapeamento e cuidado com tipos |
| 3 | Wazuh single-node em Docker Compose | ELK puro, Wazuh em VMs | Stack integrada, regras e dashboard prontos, reproduzível | Consome RAM; single point of failure |
| 4 | `localfile` + Filebeat embutido no manager | Filebeat separado lendo os logs | Menos containers e menos configuração | Acoplamento à imagem do manager; não é a arquitetura clássica de Beat |
| 5 | Regras na faixa `100100+` | Editar regras nativas | Não sobrescreve o ruleset; facilita upgrade | Precisa manter IDs e documentação |
| 6 | `same_source_ip` | `same_srcip` | `same_srcip` não funcionou com JSON no Wazuh 4.7.2 | Dependência de comportamento específico da versão |
| 7 | `pcre2` ancorado com `^...$` | Match padrão | Evita falso positivo por substring | Regex mais verbosa |
| 8 | `100103` no login bem-sucedido | Colocar na falha | Evita competir com a `100100`; login externo é mais crítico | Não detecta tentativa externa falha isolada |
| 9 | `100104` sem `frequency` | `frequency=2` com `if_matched_sid 100100` | Evita consumir os eventos da `100101` | Dispara no primeiro recon, não no segundo |
| 10 | 6 falhas no teste manual | 5 falhas | Contorna o agrupamento em lote do logcollector | Pode gerar alerta duplicado de `100101`; cooldown resolve |
| 11 | Anti-spam no dispatcher | `ignore` na regra do Wazuh | O `ignore` no Wazuh atrapalhava os testes e não era o lugar ideal | Dependência de um processo externo |
| 12 | Telegram no MVP | Teams | Setup rápido, teste no celular, API simples | Ferramenta pessoal; em empresa pode ser Teams/Slack |
| 13 | Timestamps UTC | Hora local | Correlação consistente entre containers e logs | Leitura local exige converter (-03) |
| 14 | Dashboard na 5601 | 443/8443 | Portas já ocupadas no host | URL com porta explícita |
| 15 | Dashboard como código | Criar tudo na UI | Reprodutível, idempotente, versionável | Script depende da API do Dashboards |
| 16 | `setup.sh` idempotente | Passos manuais | Reduz erro humano e documenta a instalação | Script precisa lidar com Git Bash/Windows |
| 17 | Segredos fora do Git | Commitar `.env` | Evita vazamento de token | Exige configuração local em cada máquina |
| 18 | Clones de referência fora do repositório | Publicar código de terceiros | Portfólio contém apenas trabalho próprio | Estudo local separado em `C:\CLONES-github` |

---

## 7. Bugs, hipóteses e soluções

### 7.1 Resumo dos problemas

| # | Sintoma | Causa raiz | Solução | Lição |
|---:|---|---|---|---|
| 1 | `same_srcip` nunca disparava | Campo JSON em `data.*`; comportamento do Wazuh 4.7.2 | Trocar por `same_source_ip` | Testar correlação no dado real, não só na doc |
| 2 | Regra casava `ssh.login` e `ssh.login_failed` | Match padrão por substring | `type="pcre2"` com `^...$` | Ancorar expressões |
| 3 | Regra de geo competia com a falha | Wazuh dispara só uma regra por evento | Mover `100103` para `ssh.login` | Entender a árvore de regras |
| 4 | `frequency="1"` era rejeitado | Wazuh exige frequency ≥ 2 | Usar 2 ou remover frequency | Validar com `wazuh-analysisd -t` |
| 5 | `100101` funcionava no logtest, mas não ao vivo | Estado de correlação em runtime; regra concorrente | Remover `frequency` da `100104` | `wazuh-logtest` não reproduz tudo |
| 6 | `100101` intermitente | `100104` com frequency na `100100` consumia eventos | `100104` sem frequency | Evitar duas frequency rules na mesma base |
| 7 | 5 falhas às vezes não disparavam | Logcollector agrupa eventos em lote | Testar com 6 falhas | Considerar batching |
| 8 | `ignore="60"` era suspeito | Falsa pista; não era a causa principal | Remover ignore; anti-spam no dispatcher | Não confundir sintoma com causa |
| 9 | Manager reclamava de `http.log` ausente | Arquivo ainda não existia | Criar `honeypot/logs/http.log` vazio | Garantir todos os `localfile` |
| 10 | Reinício do manager falhava | Processo/PID stale do `wazuh-apid` | `wazuh-control start` manual e depois recriar o container | Ter um plano B de subida |
| 11 | Dashboard 503 / “Security not initialized” | Índice `.opendistro_security` não existia | `securityadmin.sh` com `OPENSEARCH_JAVA_HOME` | Segurança do indexer precisa ser inicializada |
| 12 | Dashboard não resolvia o indexer | Config oficial procura `wazuh.indexer`; serviço era `wazuh-indexer` | Alias de rede `wazuh.indexer` | Conferir DNS entre containers |
| 13 | Wazuh API retornava 401 no dashboard | Credenciais do compose não batiam com o volume atual | Ajustar para os usuários padrão do manager | Credenciais de laboratório ≠ produção |
| 14 | `setup.sh` falhava no Git Bash | MSYS convertia `/var/...` para caminho Windows | `export MSYS_NO_PATHCONV=1` | Entender o shell usado |
| 15 | `setup.sh` não detectava dashboard 200 | `curl` do Windows retornava `200\r` | `tr -d '\r'` | Normalizar saída de comandos nativos |
| 16 | `100102` não aparecia quando havia falha | `100104` é mais específica e dispara antes | Esperado; testar `100102` sem falha anterior | Uma regra por evento |
| 17 | Processos de teste ficavam órfãos | Dispatcher/honeypot em background | Encerrar por PID e documentar comandos | Limpar ambiente após testes |

### 7.2 Estudo de caso: por que a `100101` não disparava ao vivo

Este foi o bug mais custoso do projeto e vale detalhar porque mostra método de investigação.

**Sintoma inicial:** no `wazuh-logtest`, cinco eventos `ssh.login_failed` disparavam a `100101` corretamente. No pipeline real, os mesmos cinco eventos geravam apenas cinco alertas `100100`; a `100101` não aparecia.

**Hipóteses levantadas:**

1. O arquivo de regras dentro do container estava desatualizado.
2. O `ignore="60"` da regra estava suprimindo alertas repetidos.
3. O campo de IP não estava sendo reconhecido pela correlação.
4. O `logcollector` estava agrupando eventos e perdendo o quinto evento.
5. Outra regra de correlação estava consumindo os eventos da `100100`.

**Experimentos:**

- Conferimos o MD5 do arquivo no host e no container: igual.
- Reiniciamos o manager e validamos que a regra era carregada.
- Ativamos `analysisd.debug=2` temporariamente; o log ficou verboso e não mostrou a decisão de correlação de forma útil. Revertemos para `0`.
- Testamos `same_source_ip` versus `same_srcip`; o segundo não funcionava com o JSON.
- Comentamos a regra `100104`; a `100101` passou a disparar.
- Reativamos a `100104` com `frequency="2"`; a `100101` voltou a falhar.
- Reimplementamos a `100104` sem `frequency`; a `100101` voltou a disparar e a `100104` disparou no primeiro comando de recon.
- Testamos 5 e 6 falhas; com 6 a taxa de sucesso ficou estável, por causa do batching.

**Causa raiz:** a `100104` original também era uma regra de `frequency` com `if_matched_sid 100100`. A coexistência de duas regras de frequency sobre a mesma base fazia com que os eventos da `100100` fossem consumidos/alterados antes de a `100101` atingir o threshold. O `ignore` foi uma falsa pista; o problema principal era a competição entre regras.

**Correção final:**

```xml
<rule id="100104" level="12" timeframe="300">
  <if_sid>100102</if_sid>
  <if_matched_sid>100100</if_matched_sid>
  <same_source_ip />
  <description>Honeypot SSH: sequência suspeita — falha de login seguida de comando de reconhecimento pelo mesmo IP.</description>
</rule>
```

**Validação:** uma falha + `whoami` gerou `100104`; cinco/seis falhas geraram `100101`; as duas mensagens chegaram ao Telegram.

**Lição:** `wazuh-logtest` é excelente para validar sintaxe e match, mas não reproduz todo o estado de correlação do `analysisd` com eventos em lote. A validação final precisa ser feita no pipeline real, com logs reais e observação do `alerts.json`.

### 7.3 Estudo de caso: dashboard 503

**Sintoma:** `https://localhost:5601` subia, mas o indexer respondia “OpenSearch Security not initialized” e o dashboard não carregava dados.

**Causa:** o índice interno `.opendistro_security` não havia sido criado no volume do indexer. A stack tinha o plugin de segurança ativo, mas sem a configuração inicial.

**Correção:**

```bash
docker exec -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk wazuh-indexer \
  bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
  -cd /usr/share/wazuh-indexer/opensearch-security -icl -nhnv \
  -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
  -cert /usr/share/wazuh-indexer/certs/admin.pem \
  -key /usr/share/wazuh-indexer/certs/admin-key.pem
```

Depois disso, o cluster ficou `green` e o login `admin/admin` funcionou.

**Correção complementar:** o dashboard oficial procura `wazuh.indexer` (com ponto). O serviço do compose usava `wazuh-indexer` (com hífen). Foi adicionado um alias de rede no compose; o `setup.sh` e a documentação registram o procedimento.

### 7.4 Estudo de caso: `setup.sh` no Git Bash

**Sintoma:** o script tentava acessar `C:\Program Files\Git\var\ossec\etc\ossec.conf` em vez de `/var/ossec/etc/ossec.conf`.

**Causa:** o Git Bash/MSYS converte argumentos que começam com `/` para caminhos Windows.

**Correção:** `export MSYS_NO_PATHCONV=1` no início do script. Também foi necessário remover `\r` da saída do `curl` ao comparar o status HTTP, porque o binário do Windows retorna `200\r`.

---

## 8. Testes e evidências

### 8.1 Testes de regras

| Teste | Entrada | Resultado esperado | Resultado observado |
|---|---|---|---|
| Base | 1 `ssh.login_failed` | `100100` nível 5 | ✅ |
| Brute-force | 5–6 falhas do mesmo IP | `100101` nível 10 | ✅ com 6 falhas |
| Recon isolado | 1 `ssh.command` `whoami` | `100102` nível 8 | ✅ |
| Sequência | falha + `whoami` do mesmo IP | `100104` nível 12 | ✅ |
| Login externo | `ssh.login` de IP público | `100103` nível 12 | ✅ |
| Coordenação | falha + comando com `100104` ativa | `100101` continua funcionando | ✅ após remover frequency |

### 8.2 Teste real do Telegram

O dispatcher foi executado em modo `--follow`. Após o ataque simulado, o terminal mostrou:

```text
[ALERTA] nível 10 | regra 100101 | enviando...
[+] Alerta enviado ao Telegram.
[ALERTA] nível 12 | regra 100104 | enviando...
[+] Alerta enviado ao Telegram.
```

As mensagens chegaram ao celular com regra, nível, IP, usuário, agente, horário e ação sugerida. O token não foi impresso nem commitado.

### 8.3 Teste do simulador

```text
[*] Atacando 127.0.0.1:2222 com 6 falhas de senha...
    tentativa 1/6: falhou
    ...
    tentativa 6/6: falhou
[*] Login + comando de recon: whoami
[+] Ataque simulado concluido. Veja os alertas no Wazuh/Telegram.
```

No Wazuh, isso gerou `100100` (falhas), `100101` (brute-force) e `100104` (sequência). O `100102` pode ser “engolido” pela `100104` quando há falha anterior, porque o Wazuh só alerta uma regra por evento.

### 8.4 Teste do dashboard

- Indexer: `status: green`, 1 node.
- Dashboard: `https://localhost:5601/app/login` com HTTP 200.
- Índice `wazuh-alerts-4.x-2026.10.20` com alertas indexados.
- Index pattern `wazuh-alerts-*` criado.
- Cinco painéis criados/atualizados via API.
- O script `create_dashboard.py` é idempotente e pode ser rodado novamente.

### 8.5 Teste do `setup.sh`

O script foi executado duas vezes no Git Bash:

- primeira execução: subiu a stack, detectou o indexer, configurou o manager e criou o dashboard;
- segunda execução: não duplicou `localfile`, atualizou os objetos existentes e confirmou o dashboard.

### 8.6 Mock do Telegram

Antes do teste real, foi usado um servidor HTTP local simulando a API do Telegram (`TELEGRAM_API_BASE`). Isso permitiu testar `--test` e `--follow` sem enviar mensagens reais. Depois, o `--setup` foi usado com o bot real e um teste chegou ao celular.

---

## 9. Segurança, riscos e limitações

### 9.1 Riscos do honeypot

- O SSH honeypot **aceita qualquer senha a partir da segunda tentativa** e registra a senha em texto claro. Isso é intencional para o laboratório, mas seria inaceitável em produção.
- O shell é falso; não há execução real de comandos, mas o serviço ainda pode ser usado para reconhecimento ou abuso de recursos.
- O honeypot não deve ser exposto diretamente à internet sem isolamento de rede, limites de conexão, monitoramento e uma política clara de resposta.
- As chaves e credenciais exibidas (`id_rsa`, `config.env`, `AWS_KEY`) são **fictícias**. Nunca usar segredos reais.

### 9.2 Credenciais e segredos

- `alerting/.env` contém o token do bot e o chat ID; está no `.gitignore` e não deve ser commitado.
- `honeypot/host.key` é gerado localmente e também não deve ser versionado.
- O dashboard usa `admin/admin` e o indexer usa segurança com certificados autoassinados; isso é aceitável só no laboratório.
- Em produção: TLS válido, senhas fortes, rotação de token, RBAC, princípio do menor privilégio e cofre de segredos.

### 9.3 Limitações técnicas

| Limitação | Impacto | Próximo passo |
|---|---|---|
| Geo é heurística CIDR, não GeoIP | Pode gerar falso positivo/negativo | Integrar MaxMind/ipinfo |
| HTTP sem regras específicas | Coleta existe, detecção automática não | Regras para `/.env`, `/admin`, POST suspeito |
| FTP não implementado | Cobertura multi-protocolo parcial | Honeypot FTP + regras |
| Filebeat embutido no manager | Menos flexibilidade que um Beat separado | Avaliar Filebeat dedicado em produção |
| Single-node | Sem HA | Cluster Wazuh |
| Dispatcher depende de Docker/tail | Pode perder eventos se o container reiniciar | Integração nativa/SOAR |
| Cooldown de 120 s | Pode esconder repetição legítima | Ajustar por criticidade |
| `ignore=300` na `100103` | Repetições em 5 min são suprimidas | Revisar política de deduplicação |
| Sem testes automatizados de regressão | Regras podem quebrar em upgrade | Pipeline de testes com `wazuh-logtest` |
| Sem retenção de longo prazo | Dificulta investigação histórica | ILM/arquivamento |

### 9.4 O que eu faria diferente em produção

1. Isolar o honeypot em VLAN dedicada, com egress bloqueado.
2. Não registrar senhas em texto claro; aplicar hash/redação.
3. Usar GeoIP real e threat intelligence.
4. Criar regras específicas para HTTP e FTP.
5. Trocar credenciais padrão, usar TLS válido e RBAC.
6. Rodar o dispatcher como serviço/sidecar, com retry e dead-letter queue.
7. Adicionar testes automatizados de regras e um pipeline CI.
8. Integrar com SOAR/TheHive/Shuffle para resposta.
9. Monitorar o próprio honeypot e o Wazuh.
10. Documentar runbooks de triagem e resposta.

---

## 10. Preparação para entrevista

### 10.1 “Explica o fluxo em 30 segundos”

“O atacante conecta no honeypot SSH na 2222. O honeypot usa Paramiko para fazer um SSH real, registra falhas, login e comandos em JSON com timestamp UTC. O Wazuh lê esses arquivos via localfile, aplica cinco regras custom e grava os alertas no alerts.json. Um dispatcher lê esse arquivo, filtra nível 10 ou mais, aplica cooldown e manda para o Telegram. O Filebeat que já vem no manager envia os alertas para o indexer, e o dashboard mostra as regras, a timeline, os IPs e os comandos.”

### 10.2 “Por que a 100104 não usa frequency?”

“Porque eu tinha duas regras de frequency apontando para a 100100. A segunda consumia os eventos e impedia a 100101 de atingir o threshold. Eu removi o frequency da 100104 e usei if_sid no comando atual mais if_matched_sid na falha anterior, com same_source_ip. Assim a sequência dispara no primeiro comando de recon e a 100101 volta a funcionar.”

### 10.3 “Por que testar com 6 falhas?”

“O logcollector pode agrupar linhas em lote; em alguns testes a quinta falha era avaliada antes de entrar na janela de correlação. A sexta garantia o disparo. Em um ataque real há muito mais tentativas, então isso é uma questão de teste reproduzível, não uma limitação do threshold.”

### 10.4 “Por que same_source_ip?”

“Com o log JSON, o IP fica em data.srcip. No Wazuh 4.7.2, same_srcip não disparou de forma confiável; same_source_ip funcionou. Eu validei no pipeline real, não só no logtest.”

### 10.5 “O que é o Filebeat aqui?”

“A imagem oficial do Wazuh Manager já roda um Filebeat interno que envia o alerts.json para o indexer. Eu não tenho um container separado de Filebeat. Os logs do honeypot entram no manager por localfile; o Filebeat é a etapa de envio dos alertas para o indexer/dashboard.”

### 10.6 “Como você debugou o bug mais difícil?”

“Eu comecei comparando logtest com o pipeline real. Confirmei que a regra estava carregada no container, testei same_source_ip, ativei debug do analysisd e depois isolei a 100104. Quando desativei a 100104, a 100101 voltou a disparar; quando reativei a versão com frequency, voltou a falhar. A causa era a competição entre duas regras de frequency na mesma base. Removi o frequency da 100104 e padronizei o teste com 6 falhas por causa do batching.”

### 10.7 “O que é um falso positivo e como você reduziria?”

“É um alerta que não representa um incidente real. Eu reduziria com contexto: listas de IPs confiáveis, GeoIP, horário de acesso, comportamento esperado por usuário, correlação com outros eventos e tuning do threshold. Também separaria severidade de confiança e usaria cooldown para não transformar ruído em fadiga de alerta.”

### 10.8 “O que faria em produção?”

“TLS válido, RBAC, segredos em cofre, honeypot isolado, GeoIP, regras HTTP/FTP, testes automatizados, HA, retenção, integração com SOAR e runbooks. Também trocaria as credenciais padrão e revisaria a política de retenção de senhas.”

### 10.9 “Qual a diferença entre Kibana e Wazuh Dashboard?”

“O Wazuh Dashboard é baseado no OpenSearch Dashboards, que é um fork do Kibana. A especificação fala Kibana genericamente; na prática, a stack Wazuh usa OpenSearch Dashboards com o plugin Wazuh. O conceito de index pattern, visualizações e dashboard é o mesmo.”

### 10.10 “Quais são os riscos de rodar um honeypot?”

“O honeypot pode ser usado para reconhecimento, abuso de recursos ou como pivô se não estiver isolado. Ele não deve ter credenciais reais, deve ter egress bloqueado, limites de conexão e monitoramento. Também é importante não registrar dados sensíveis desnecessariamente.”

---

## 11. Pendências e próximos passos

### Concluído

- [x] Honeypot SSH real com comandos e credenciais.
- [x] Honeypot HTTP com iscas e User-Agent.
- [x] Simulador de ataque SSH.
- [x] Ingestão no Wazuh via `localfile` JSON.
- [x] Cinco regras custom testadas.
- [x] Brute-force, sequência e login externo disparando.
- [x] Dispatcher Wazuh → Telegram com token seguro.
- [x] Mensagens reais no celular.
- [x] Dashboard com cinco painéis.
- [x] `setup.sh` idempotente.
- [x] Documentação de arquitetura, regras e demo.

### Pendente

- [ ] Gravar o vídeo de 2–3 min usando `simulate_attack.py`.
- [ ] Fazer a entrevista simulada de SOC.
- [ ] Adicionar regras específicas para HTTP.
- [ ] Avaliar honeypot FTP (opcional).
- [ ] Integrar GeoIP real.
- [ ] Endurecer credenciais/TLS/RBAC.
- [ ] Criar testes automatizados de regressão das regras.
- [ ] Fazer push dos commits locais quando o usuário autorizar.
- [ ] Retomar o portfólio HTML/CSS somente quando solicitado.

---

## 12. Como reproduzir

### 12.1 Subir a stack e configurar

No Git Bash (Windows):

```bash
cd /c/GIT-GITHUB/Purple-Honeypot-SIEM
bash deploy/setup.sh
```

O script:
- sobe indexer, manager e dashboard;
- inicializa a segurança do indexer se necessário;
- configura o `localfile`;
- cria/atualiza o dashboard.

### 12.2 Configurar o Telegram

```powershell
python alerting/webhook_dispatcher.py --setup
```

O wizard pede o token sem exibir, salva em `alerting/.env`, descobre o chat ID e envia um teste.

Teste manual:

```powershell
python alerting/webhook_dispatcher.py --test
python alerting/webhook_dispatcher.py --test --dry-run
```

### 12.3 Rodar o honeypot e o dispatcher

Terminal 1:

```powershell
python honeypot/ssh_honeypot.py
```

Terminal 2:

```powershell
python alerting/webhook_dispatcher.py --follow
```

Terminal 3 (opcional, para gerar o ataque):

```powershell
python honeypot/simulate_attack.py
```

Para sair de uma sessão SSH manual, use `~.`. No PowerShell, `Ctrl+C` não encerra a sessão SSH da mesma forma.

### 12.4 Abrir o dashboard

```text
https://localhost:5601
```

Login de laboratório: `admin` / `admin`.

Dashboard: **Dashboards → Purple Honeypot SIEM**.

### 12.5 Conferir alertas

```powershell
docker exec wazuh-manager tail -20 /var/ossec/logs/alerts/alerts.json
```

Ou, no dashboard, use os painéis de timeline e alertas recentes.

### 12.6 Recriar o dashboard via script

```powershell
python siem/create_dashboard.py
```

---

## 13. Apêndices

### 13.1 Mapa de arquivos

```text
Purple-Honeypot-SIEM/
├── README.md
├── honeypot/
│   ├── ssh_honeypot.py
│   ├── http_honeypot.py
│   ├── simulate_attack.py
│   ├── host.key              # local, não versionado
│   └── logs/
│       ├── ssh.log
│       └── http.log
├── siem/
│   ├── docker-compose.yml
│   ├── filebeat.yml           # referência documental
│   ├── create_dashboard.py
│   ├── OSSEC-MANUAL-CHANGES.md
│   └── custom_rules/
│       └── bruteforce_custom.xml
├── alerting/
│   ├── webhook_dispatcher.py
│   ├── .env.example
│   ├── .env                   # local, gitignored
│   └── teams_alert.ps1
├── deploy/
│   └── setup.sh
├── docs/
│   ├── architecture.md
│   ├── demo_video_link.md
│   └── RELATORIO.md
└── .gitignore
```

### 13.2 Commits relevantes

| Commit | Descrição |
|---|---|
| `506da3f` | Regras 100100–100104 testadas + dispatcher Wazuh → Telegram |
| `99a55af` | 100104 sem frequency e sequência testada no Telegram real |
| `e1e6775` | Dashboard com painéis e `setup.sh` idempotente |
| `898c9e2` | Painel de comandos executados no dashboard |

Os commits estão **apenas locais**; nenhum push foi feito sem autorização.

### 13.3 Glossário rápido

- **Honeypot:** serviço falso que atrai e registra atividade de atacantes.
- **SIEM:** sistema que coleta, correlaciona e alerta sobre eventos de segurança.
- **Wazuh Manager:** componente que recebe logs, aplica decoders/regras e gera alertas.
- **Analysisd:** motor do Wazuh que avalia as regras.
- **Localfile:** configuração do Wazuh para ler um arquivo local.
- **Filebeat:** agente de envio de logs; aqui está embutido no manager.
- **SID:** ID da regra do Wazuh.
- **Level:** severidade do alerta (0–16).
- **Frequency/timeframe:** quantas ocorrências em quanto tempo.
- **`if_matched_sid`:** condição que exige um alerta anterior de outra regra.
- **`same_source_ip`:** exige que os eventos correlacionados tenham o mesmo IP de origem.
- **Index pattern:** padrão de índice usado pelo dashboard (`wazuh-alerts-*`).
- **Brute-force:** tentativa repetida de autenticação.
- **Reconhecimento:** comandos para descobrir usuário, sistema e arquivos após o acesso.
- **Falso positivo:** alerta que não corresponde a um incidente real.
- **Fadiga de alerta:** perda de atenção causada por excesso de notificações.

---

## Conclusão

O projeto saiu de “honeypot que grava log” para um **pipeline completo de laboratório**: coleta estruturada, correlação com regras próprias, alerta no celular, dashboard e instalação reproduzível. O maior aprendizado não foi a sintaxe do Wazuh, mas o método de investigação: comparar o teste isolado com o runtime real, isolar variáveis, confirmar a causa e só então documentar a correção.

O que ainda separa este MVP de produção está listado de forma explícita: GeoIP real, regras HTTP/FTP, isolamento de rede, credenciais fortes, testes automatizados e operação com HA. Para a entrevista, a história mais forte é a do bug da `100101`: um problema intermitente que parecia sintaxe, mas era **competição entre regras de correlação** e **agrupamento de eventos em lote**.
