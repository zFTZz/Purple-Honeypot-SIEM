#!/usr/bin/env bash
# Instalacao/verificacao do Purple Honeypot SIEM.
# Rode na raiz do repo: bash deploy/setup.sh
# Testado no Git Bash (Windows) com Docker Desktop.
set -euo pipefail

# Git Bash no Windows converte /var/... para C:\Program Files\Git\var\...
# e quebra os comandos docker exec. Desliga essa conversao (ignorado no Linux).
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f siem/docker-compose.yml)
INDEXER_HEALTH="https://localhost:9200/_cluster/health"
DASHBOARD="https://localhost:5601"

echo "=== Purple Honeypot SIEM - setup ==="
command -v docker >/dev/null || { echo "[!] Docker nao encontrado no PATH."; exit 1; }
docker info >/dev/null 2>&1 || { echo "[!] Docker Desktop nao esta rodando."; exit 1; }
command -v curl >/dev/null || { echo "[!] curl nao encontrado."; exit 1; }

echo "[*] Pastas e logs..."
mkdir -p honeypot/logs
touch honeypot/logs/ssh.log honeypot/logs/http.log

if [ ! -f alerting/.env ]; then
  cp alerting/.env.example alerting/.env
  echo "[+] alerting/.env criado. Depois rode: python alerting/webhook_dispatcher.py --setup"
fi

echo "[*] Subindo containers (indexer, manager, dashboard)..."
"${COMPOSE[@]}" up -d

echo "[*] Aguardando o indexer responder..."
INDEXER_READY=0
for _ in $(seq 1 60); do
  CODE="$(curl -k -s -o /dev/null -w '%{http_code}' "$INDEXER_HEALTH" || true)"
  if [ "$CODE" != "000" ]; then INDEXER_READY=1; break; fi
  sleep 2
done
if [ "$INDEXER_READY" -ne 1 ]; then
  echo "[!] Indexer nao respondeu em https://localhost:9200."
  echo "    Veja: docker logs wazuh-indexer --tail 50"
  exit 1
fi

echo "[*] Verificando o indice de seguranca do indexer..."
HEALTH="$(curl -k -s -u admin:admin "$INDEXER_HEALTH" || true)"
if ! printf '%s' "$HEALTH" | grep -q '"status"'; then
  echo "[*] Inicializando seguranca (primeira subida)..."
  docker exec -e OPENSEARCH_JAVA_HOME=/usr/share/wazuh-indexer/jdk wazuh-indexer \
    bash /usr/share/wazuh-indexer/plugins/opensearch-security/tools/securityadmin.sh \
    -cd /usr/share/wazuh-indexer/opensearch-security -icl -nhnv \
    -cacert /usr/share/wazuh-indexer/certs/root-ca.pem \
    -cert /usr/share/wazuh-indexer/certs/admin.pem \
    -key /usr/share/wazuh-indexer/certs/admin-key.pem
  sleep 5
  HEALTH="$(curl -k -s -u admin:admin "$INDEXER_HEALTH" || true)"
fi
if ! printf '%s' "$HEALTH" | grep -q '"status"'; then
  echo "[!] Seguranca do indexer ainda nao inicializou."
  echo "    Veja: docker logs wazuh-indexer --tail 50"
  exit 1
fi
echo "[+] Indexer OK."

if docker exec wazuh-manager true >/dev/null 2>&1; then
  if ! docker exec wazuh-manager grep -q '/var/log/honeypot/ssh.log' /var/ossec/etc/ossec.conf; then
    echo "[*] Adicionando os localfile do honeypot no ossec.conf (volume)..."
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
</ossec_config>
EOF
    docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-analysisd -t' || {
      echo "[!] ossec.conf invalido; veja a mensagem acima."; exit 1;
    }
    docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control restart' >/dev/null 2>&1 || true
    sleep 8
    docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control status' | grep -q 'wazuh-analysisd is running' || \
      docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control start' >/dev/null 2>&1 || true
  fi
  echo "[+] Manager configurado."
else
  echo "[!] Container wazuh-manager nao esta rodando; pulei o localfile."
fi

echo "[*] Aguardando o dashboard..."
for _ in $(seq 1 60); do
  CODE="$(curl -k -s -o /dev/null -w '%{http_code}' "$DASHBOARD/app/login" | tr -d '\r' || true)"
  if [ "$CODE" = "200" ]; then break; fi
  sleep 2
done
CODE="$(curl -k -s -o /dev/null -w '%{http_code}' "$DASHBOARD/app/login" | tr -d '\r' || true)"
if [ "$CODE" = "200" ]; then
  echo "[+] Dashboard OK."
  if command -v python >/dev/null 2>&1; then
    echo "[*] Criando/atualizando o dashboard e os paineis..."
    python siem/create_dashboard.py || echo "[!] Nao consegui criar o dashboard; abra o menu Dashboards e importe/edite manualmente."
  else
    echo "[!] Python nao encontrado; crie o dashboard pela interface."
  fi
else
  echo "[!] Dashboard ainda nao respondeu em $DASHBOARD."
  echo "    Veja: docker logs wazuh-dashboard --tail 50"
fi

echo
echo "=== Pronto ==="
echo "Dashboard:  $DASHBOARD  (admin/admin no laboratorio)"
echo "Regras:     siem/custom_rules/bruteforce_custom.xml"
echo "Telegram:   python alerting/webhook_dispatcher.py --setup"
echo "Honeypot:   python honeypot/ssh_honeypot.py"
echo "Dispatcher: python alerting/webhook_dispatcher.py --follow"
echo "Simulador:  python honeypot/simulate_attack.py"
echo
echo "Lembrete: nao commite alerting/.env nem honeypot/host.key."
