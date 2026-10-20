# Arquitetura — Purple Honeypot SIEM

## Fluxo real (o que está implementado)

```
[Atacante / scanner]
  | ssh admin@host -p 2222            | curl http://host:8080/.env
  v                                   v
[ssh_honeypot.py]                   [http_honeypot.py]
  paramiko, handshake SSH real        HTTP na 8080, iscas /.env /admin
  |                                   |
  +---------------+-------------------+
                  v
        honeypot/logs/ssh.log e http.log
        (1 JSON por linha, timestamp UTC)
                  |
                  v
        Wazuh manager (container)
        localfile log_format=json
                  |
                  +--> analysisd + custom_rules/bruteforce_custom.xml
                  |        100100 falha
                  |        100101 brute-force
                  |        100102 recon
                  |        100103 login externo
                  |        100104 sequência
                  |
                  +--> /var/ossec/logs/alerts/alerts.json
                  |        |
                  |        +--> webhook_dispatcher.py --follow
                  |                filtra level >= 10 + cooldown
                  |                -> API do Telegram -> celular
                  |
                  +--> Filebeat (já vem no container do manager)
                           -> Wazuh Indexer (9200) -> Dashboard (5601)
```

## Decisões e o porquê

- **Portas 2222/8080**: rodam sem root e não brigam com SSH/web de verdade.
- **JSON lines + UTC com `Z`**: o Wazuh decodifica sem regex artesanal e o Kibana ordena corretamente.
- **SSH com paramiko**: socket em texto puro quebrava o cliente `ssh` real (`kex_exchange_identification`). O paramiko faz o handshake criptográfico e permite capturar comandos.
- **1ª senha sempre falha, 2ª entra**: cria `ssh.login_failed` de verdade para a regra de brute-force poder disparar. Em produção, nunca se registra a senha.
- **Thread por conexão**: dois atacantes simultâneos não travam o honeypot.
- **Wazuh lê os logs por `localfile`**: é o jeito nativo de ingerir arquivo no manager. O Filebeat da stack oficial fica dentro do container e envia os **alertas** para o indexer; ele não substitui o `localfile`.
- **Regra custom, não só default**: o ruleset padrão é igual para todo mundo; a regra própria prova que você entendeu o dado e sabe detectar.
- **Telegram para o alerta**: API simples, testável no celular e sem depender de conta corporativa. O dispatcher roda no host, lê o `alerts.json` via `docker exec` e tem anti-spam.
- **Só uma regra dispara por evento no Wazuh**: por isso a geo (100103) foi colocada no evento de login bem-sucedido externo, para não "engolir" a 100100 e quebrar o brute-force.
- **100104 sem `frequency`**: uma segunda regra de frequency apontando para a 100100 consumia os eventos e impedia a 100101 de disparar. Com `if_sid` (evento atual) + `if_matched_sid` (falha anterior), a sequência é detectada no primeiro comando de recon.
- **6 falhas no teste manual**: o logcollector pode agrupar linhas em lote; a 5ª tentativa às vezes é avaliada antes de entrar na janela. A 6ª garante o disparo e o dispatcher evita spam.
- **Simulador de ataque**: `honeypot/simulate_attack.py` é um cliente SSH separado, usado só no laboratório para gerar os eventos sem digitar senha manualmente. Ele não faz parte do honeypot e não é necessário em produção.

## Pastas de evidência (padrão do CJCA)

```
Evidence/
├── Findings/          (1 pasta por regra: bruteforce, sequencia, geo)
├── Scans/             (nmap/ffuf contra o honeypot)
├── Logging output/    (ssh.log, http.log, alerts.json)
└── Notes/             (Activity Log: o que rodei, quando, com que IP)
```

## Limitações honestas (para falar em entrevista)

- O geo não usa GeoIP real; ele compara com faixas internas conhecidas. Em produção: enriquecer com MaxMind/ipinfo.
- O honeypot é de laboratório: aceita qualquer senha e guarda a senha no JSON. Em produção, isso seria redigido.
- O dispatcher lê o `alerts.json` via Docker; em produção, o ideal é uma integração nativa do Wazuh ou um SOAR (Shuffle/DFIR-IRIS).
- O dashboard e os usuários `admin/admin` são de laboratório; em produção, TLS com certificados válidos, senhas fortes e RBAC do Wazuh.
