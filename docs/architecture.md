# Arquitetura — Purple Honeypot SIEM

## Fluxo implementado

```text
[Atacante / scanner / simulador]
  | ssh admin@host -p 2222            | curl http://host:8080/.env        | ftp host 2121
  v                                   v                                   v
[ssh_honeypot.py]                   [http_honeypot.py]                  [ftp_honeypot.py]
  Paramiko, handshake SSH real        HTTP com iscas /.env /admin         socket FTP, iscas LIST/RETR
  |                                   |                                   |
  +-------------------------------+---+-----------------------------------+
                                  v
                    honeypot/logs/ssh.log, http.log, ftp.log
                    (um JSON por linha, timestamp UTC)
                                  |
                                  v
                    Wazuh Manager (container)
                    localfile log_format=json
                                  |
                                  +--> analysisd + custom_rules/bruteforce_custom.xml
                                  |        100100 falha SSH          100105 scanner HTTP
                                  |        100101 brute-force SSH    100106 isca/traversal
                                  |        100102 recon SSH          100107 POST
                                  |        100103 login externo      100108 scan sequencial
                                  |        100104 sequência SSH      100109/100110 FTP
                                  |
                                  +--> /var/ossec/logs/alerts/alerts.json
                                  |        |
                                  |        +--> webhook_dispatcher.py --follow
                                  |                nível >= 10 + cooldown
                                  |                -> API do Telegram -> celular
                                  |
                                  +--> Filebeat (embutido no manager)
                                           -> Wazuh Indexer (9200) -> Dashboard (5601)
```

## Decisões de arquitetura

- **Portas 2222, 8080 e 2121**: permitem executar sem root e evitam conflito com serviços reais do host.
- **JSON lines com timestamp UTC**: o Wazuh decodifica os campos sem regex artesanal e o dashboard ordena os eventos corretamente.
- **SSH com Paramiko**: um socket em texto puro não é compatível com o cliente `ssh` real. O Paramiko faz o handshake criptográfico e permite registrar autenticação e comandos.
- **Primeira senha falha, segunda entra**: gera eventos reais de falha para as regras de brute-force. Em produção, senhas não devem ser registradas.
- **Uma thread por conexão**: conexões simultâneas não bloqueiam o honeypot.
- **Ingestão por `localfile`**: é o mecanismo nativo do Wazuh para ler arquivos no manager. O Filebeat da imagem oficial envia os alertas para o indexer; ele não substitui o `localfile`.
- **Regras custom em vez de apenas o ruleset padrão**: o ruleset nativo é genérico; as regras próprias comprovam o entendimento do dado e das técnicas detectadas.
- **Telegram para o alerta**: API simples, testável no celular e sem dependência de conta corporativa. O dispatcher roda no host, lê o `alerts.json` via `docker exec` e aplica cooldown.
- **Uma regra por evento no Wazuh**: a regra de origem externa (`100103`) fica no login bem-sucedido para não competir com a `100100` e preservar a correlação de brute-force.
- **`100104` sem `frequency`**: uma segunda regra de frequency sobre a `100100` consumia eventos e impedia a `100101` de disparar. A sequência usa `if_sid` + `if_matched_sid`, disparando no primeiro comando de reconhecimento após uma falha.
- **Seis falhas no teste manual**: o logcollector pode agrupar linhas em lote; a sexta tentativa garante o gatilho da `100101` no laboratório.
- **Simulador separado**: `honeypot/simulate_attack.py` é um cliente SSH controlado, usado para gerar eventos sem digitação manual. Ele não faz parte do honeypot.

## Validação do fluxo

O fluxo é validado em quatro pontos:

1. **Coleta**: os três honeypots gravam JSON em `honeypot/logs/`.
2. **Decodificação**: o manager lê os arquivos via `localfile` com `log_format=json`.
3. **Detecção**: as regras `100100–100110` geram alertas em `alerts.json`.
4. **Entrega**: o dashboard consome o índice `wazuh-alerts-*`; o dispatcher entrega os alertas de nível ≥ 10 no Telegram.

## Limitações e próximos passos

- A regra de origem externa (`100103`) é uma heurística CIDR, não GeoIP. Em produção, enriquecer com MaxMind ou ipinfo.
- O honeypot é de laboratório: aceita qualquer senha e armazena a senha no JSON. Em produção, esse campo deve ser redigido ou descartado.
- O dispatcher depende de Docker e `tail`; em produção, prefira integração nativa do Wazuh ou um SOAR.
- O dashboard e o usuário `admin/admin` são de laboratório. Em produção: TLS com certificados válidos, senhas fortes e RBAC.
- A stack é single-node. HA, retenção de longo prazo e testes automatizados de regressão ficam no roadmap.
