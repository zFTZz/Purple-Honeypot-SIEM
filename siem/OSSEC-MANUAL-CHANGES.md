# Configuração manual do ossec.conf (volume do container)

O volume `siem_wazuh-manager-etc` armazena `/var/ossec/etc` e sobrevive a
reinícios do container. Se o volume for removido, recrie os blocos abaixo ou
execute novamente `deploy/setup.sh`, que adiciona apenas os `localfile` ausentes.

## 1. Ingestão dos logs do honeypot (JSON lines)

```sh
docker exec -i wazuh-manager tee -a /var/ossec/etc/ossec.conf >/dev/null <<'EOF'

<!-- Purple Honeypot SIEM: logs JSON -->
<ossec_config>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/honeypot/ssh.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/honeypot/http.log</location>
  </localfile>
  <localfile>
    <log_format>json</log_format>
    <location>/var/log/honeypot/ftp.log</location>
  </localfile>
</ossec_config>
EOF
docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-analysisd -t && echo CONFIG-OK'
docker restart wazuh-manager
```

Os arquivos `ssh.log`, `http.log` e `ftp.log` precisam existir. O `setup.sh`
cria os três automaticamente; para criar manualmente:

```powershell
New-Item -ItemType File -Force honeypot/logs/http.log
New-Item -ItemType File -Force honeypot/logs/ftp.log
```

## 2. O que já está versionado no repositório

- `siem/docker-compose.yml`: mounts das regras e de `honeypot/logs`.
- `siem/custom_rules/bruteforce_custom.xml`: regras 100100–100110 (SSH/HTTP/FTP).
- `.gitignore`: `honeypot/logs/`, `alerting/.env` e `honeypot/host.key`.

## 3. Debug temporário

A opção `logall yes` no `ossec.conf` grava todos os eventos em `archives.json`.
Foi usada apenas para comprovar a ingestão e depois revertida. Não deixe ativada
em produção: aumenta o consumo de disco e a exposição de dados sensíveis.

```sh
docker exec wazuh-manager grep -n logall /var/ossec/etc/ossec.conf
```

## 4. Validação rápida

```powershell
docker exec wazuh-manager sh -c "/var/ossec/bin/wazuh-analysisd -t"
docker exec wazuh-manager sh -c "grep '100101' /var/ossec/logs/alerts/alerts.json | tail -1"
```
