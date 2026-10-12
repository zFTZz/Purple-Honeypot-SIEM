# Arquitetura — Purple Honeypot SIEM

## Fluxo
```
[Atacante internet/lan]
  | ssh admin@alvo -p 2222 / curl /.env / ffuf /admin
  v
[Honeypot Python]
  ssh_honeypot.py (paramiko 2222) -> honeypot/logs/ssh.log (JSON lines)
  http_honeypot.py (8080)         -> honeypot/logs/http.log (JSON lines)
  captura: src_ip, user, password, command, path, user-agent, suspicious:true/false
  v
[Filebeat] lê logs/*.log, adiciona timestamp UTC, envia pro Wazuh
  v
[Wazuh Docker] aplica custom_rules/*.xml
  - bruteforce_custom.xml
  - suspicious_sequence.xml
  - geo_anomaly.xml
  v
[Alerting] webhook_dispatcher.py -> Telegram / teams_alert.ps1 -> Teams
  v
[Kibana] dashboard: top IPs, timeline, nuvem de comandos (whoami, id, ls, cat id_rsa)
```

## Por que assim?
- Porta 2222 e 8080: rodam sem root, não brigam com SSH/web real.
- JSON lines + UTC com Z: Filebeat/Wazuh/Kibana entendem sem regex louca e ordenam certo.
- Aceitar qualquer senha: prende atacante mais tempo = mais telemetria (em prod real NUNCA logue senha).
- Thread por IP: 2 atacantes juntos não travam.
- Regra custom e não só default: default todo mundo tem, custom prova que você sabe detectar.

## Pastas de evidência (padrão do CJCA)
```
Evidence/
├── Findings/ (1 pasta por regra: bruteforce, sequencia, geo)
├── Scans/ (nmap, ffuf contra o honeypot pra provar que detecta)
├── Logging output/ (ssh.log, http.log, wazuh alerts)
└── Notes/ (Activity Log: o que rodei, quando, com que IP)
```
