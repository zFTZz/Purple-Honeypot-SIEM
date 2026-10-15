# Mudanças manuais no ossec.conf (DENTRO do container — NÃO estão no git!)

Se o volume `siem_wazuh-manager-etc` for apagado, refazer via `docker exec`:

```sh
cat >> /var/ossec/etc/ossec.conf <<'EOF'

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
</ossec_config>
EOF
/var/ossec/bin/wazuh-analysisd -t && echo CONFIG-OK
docker restart wazuh-manager
```

O que JÁ está no git e volta sozinho: `docker-compose.yml` (mounts),
`custom_rules/bruteforce_custom.xml` (regras 100100/100101).

Débito: `filebeat.yml` vazio (pipeline hoje lê direto via mount, sem Filebeat).
Debug temporário já revertido: `logall yes` (era só p/ provar ingestão).
