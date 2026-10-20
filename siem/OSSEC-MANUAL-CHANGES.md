# Mudanças manuais no ossec.conf (DENTRO do container — NÃO estão no git!)

O volume `siem_wazuh-manager-etc` guarda o `/var/ossec/etc` e sobrevive a
`docker restart`. Se o volume for apagado, refazer os blocos abaixo via
`docker exec` (ou recriar o volume com a config default da imagem).

## 1. Ingestão dos logs do honeypot (JSON lines)

```sh
docker exec -i wazuh-manager tee -a /var/ossec/etc/ossec.conf >/dev/null <<'EOF'

<!-- Projeto 1: honeypot logs em JSON -->
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

Os arquivos `http.log` e `ftp.log` precisam existir. Se ainda não rodou os honeypots, crie vazios:

```powershell
New-Item -ItemType File -Force honeypot/logs/http.log
New-Item -ItemType File -Force honeypot/logs/ftp.log
```

## 2. O que já está no git e volta sozinho

- `siem/docker-compose.yml`: mounts das regras e de `honeypot/logs`.
- `siem/custom_rules/bruteforce_custom.xml`: regras 100100-100110 (SSH/HTTP/FTP).
- `.gitignore`: `honeypot/logs/` e `alerting/.env` não vão pro repositório.

## 3. Debug temporário

`logall yes` no ossec.conf grava todos os eventos em `archives.json`; foi usado
só para provar a ingestão e depois revertido. Não deixe ligado em produção
(disco e dado sensível).

```sh
docker exec wazuh-manager grep -n logall /var/ossec/etc/ossec.conf
```

## 4. Validação rápida

```powershell
docker exec wazuh-manager sh -c "/var/ossec/bin/wazuh-analysisd -t"
docker exec wazuh-manager sh -c "grep '100101' /var/ossec/logs/alerts/alerts.json | tail -1"
```
