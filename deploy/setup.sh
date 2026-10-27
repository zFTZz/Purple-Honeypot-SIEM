#!/usr/bin/env bash
# Instalação e verificação do Purple Honeypot SIEM.
# Execute na raiz do repositório: bash deploy/setup.sh
# Testado no Git Bash (Windows) com Docker Desktop.
set -euo pipefail

# O Git Bash converte /var/... para C:\Program Files\Git\var\... e quebra
# comandos docker exec. Desabilita a conversão (ignorado em Linux/macOS).
export MSYS_NO_PATHCONV=1

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
COMPOSE=(docker compose -f siem/docker-compose.yml)
INDEXER_HEALTH="https://localhost:9200/_cluster/health"
DASHBOARD="https://localhost:5601"

echo "=== Purple Honeypot SIEM — setup ==="
command -v docker >/dev/null || { echo "[!] Docker não encontrado no PATH."; exit 1; }
docker info >/dev/null 2>&1 || { echo "[!] Docker Desktop não está em execução."; exit 1; }
command -v curl >/dev/null || { echo "[!] curl não encontrado."; exit 1; }

echo "[*] Preparando diretórios e arquivos de log..."
mkdir -p honeypot/logs
touch honeypot/logs/ssh.log honeypot/logs/http.log honeypot/logs/ftp.log

if [ ! -f alerting/.env ]; then
  cp alerting/.env.example alerting/.env
  echo "[+] alerting/.env criado. Depois execute: python alerting/webhook_dispatcher.py --setup"
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
  echo "[!] Indexer não respondeu em https://localhost:9200."
  echo "    Veja: docker logs wazuh-indexer --tail 50"
  exit 1
fi

echo "[*] Verificando o índice de segurança do indexer..."
HEALTH="$(curl -k -s -u admin:admin "$INDEXER_HEALTH" || true)"
if ! printf '%s' "$HEALTH" | grep -q '"status"'; then
  echo "[*] Inicializando a segurança do indexer (primeira subida)..."
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
  echo "[!] A segurança do indexer ainda não inicializou."
  echo "    Veja: docker logs wazuh-indexer --tail 50"
  exit 1
fi
echo "[+] Indexer OK."

# Na primeira subida o manager só popula o volume /var/ossec/etc depois que o
# indexer fica seguro. Sem essa espera, o tee abaixo pode criar um ossec.conf
# parcial e fazer o entrypoint pular a cópia dos arquivos padrão
# (ar.conf, decoders, rules, client.keys) — deixa o manager inutilizável.
echo "[*] Aguardando o manager popular o volume /var/ossec/etc..."
MANAGER_READY=0
for _ in $(seq 1 90); do
  if docker exec wazuh-manager sh -c 'test -s /var/ossec/etc/ossec.conf' 2>/dev/null && \
     docker exec wazuh-manager sh -c 'test -f /var/ossec/etc/shared/ar.conf' 2>/dev/null; then
    MANAGER_READY=1
    break
  fi
  sleep 2
done
if [ "$MANAGER_READY" -ne 1 ]; then
  echo "[!] wazuh-manager não terminou de inicializar (ossec.conf ou ar.conf ausente)."
  echo "    Veja: docker logs wazuh-manager --tail 50"
  exit 1
fi
echo "[+] Manager OK."

# A cópia oficial da regra custom (via /wazuh-config-mount) acontece só no
# start do container; sincronizamos aqui para refletir edições locais sem
# reiniciar tudo. Se o conteúdo mudou, o manager reinicia para recarregar.
echo "[*] Sincronizando a regra custom do container..."
# O -i é obrigatório: sem ele o docker exec não encaminha o stdin e o cmp
# compara o arquivo contra EOF vazio → sempre "diferente" → restart à toa.
if docker exec -i wazuh-manager sh -c 'cmp -s /var/ossec/etc/rules/bruteforce_custom.xml -' \
    < siem/custom_rules/bruteforce_custom.xml 2>/dev/null; then
  echo "[=] regra custom já atualizada."
else
  docker cp siem/custom_rules/bruteforce_custom.xml wazuh-manager:/var/ossec/etc/rules/bruteforce_custom.xml
  echo "[+] regra custom copiada; reiniciando o manager para carregar."
  docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control restart' >/dev/null 2>&1 || true
  sleep 8
fi

# Adiciona somente os localfiles que ainda não existem no volume do manager.
adicionar_localfiles() {
  local faltantes=()
  local arquivo
  for arquivo in ssh http ftp; do
    if ! docker exec wazuh-manager grep -q "/var/log/honeypot/${arquivo}.log" /var/ossec/etc/ossec.conf 2>/dev/null; then
      faltantes+=("$arquivo")
    fi
  done

  if [ "${#faltantes[@]}" -eq 0 ]; then
    echo "[=] localfiles do honeypot já configurados."
    return
  fi

  echo "[*] Adicionando localfile: ${faltantes[*]}"
  {
    echo ""
    echo "<!-- Purple Honeypot SIEM: logs JSON -->"
    echo "<ossec_config>"
    for arquivo in "${faltantes[@]}"; do
      echo "  <localfile>"
      echo "    <log_format>json</log_format>"
      echo "    <location>/var/log/honeypot/${arquivo}.log</location>"
      echo "  </localfile>"
    done
    echo "</ossec_config>"
  } | docker exec -i wazuh-manager tee -a /var/ossec/etc/ossec.conf >/dev/null

  docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-analysisd -t' || {
    echo "[!] ossec.conf inválido; veja a mensagem acima."; exit 1;
  }
  docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control restart' >/dev/null 2>&1 || true
  sleep 8
  docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control status' | grep -q 'wazuh-analysisd is running' || \
    docker exec wazuh-manager sh -c '/var/ossec/bin/wazuh-control start' >/dev/null 2>&1 || true
}

if docker exec wazuh-manager true >/dev/null 2>&1; then
  adicionar_localfiles
  echo "[+] Manager configurado."
else
  echo "[!] Container wazuh-manager não está em execução; localfiles não configurados."
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
  PYTHON_BIN="$(command -v python3 || command -v python || true)"
  if [ -n "$PYTHON_BIN" ]; then
    echo "[*] Criando/atualizando o dashboard e os painéis..."
    "$PYTHON_BIN" siem/create_dashboard.py || echo "[!] Não foi possível criar o dashboard; abra o menu Dashboards e ajuste manualmente."
  else
    echo "[!] Python não encontrado; crie o dashboard pela interface."
  fi
else
  echo "[!] O dashboard ainda não respondeu em $DASHBOARD."
  echo "    Veja: docker logs wazuh-dashboard --tail 50"
fi

echo
echo "=== Pronto ==="
echo "Dashboard:  $DASHBOARD  (admin/admin no laboratório)"
echo "Regras:     siem/custom_rules/bruteforce_custom.xml"
echo "Telegram:   python alerting/webhook_dispatcher.py --setup"
echo "Honeypot:   python honeypot/ssh_honeypot.py"
echo "Dispatcher: python alerting/webhook_dispatcher.py --follow"
echo "Simulador:  python honeypot/simulate_attack.py"
echo
echo "Lembrete: não faça commit de alerting/.env nem de honeypot/host.key."
