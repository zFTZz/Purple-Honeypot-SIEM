"""Testes do dispatcher Wazuh -> Telegram.

Nada aqui envia mensagem: todo caminho de envio passa por `enviar_telegram` com
`--dry-run` ou por um mock. O que é testado é o que quebra na prática: filtro de
nível, cooldown por regra+IP, formatação/escape da mensagem e a tolerância a
linhas truncadas do `alerts.json`.
"""
import json
import os
import subprocess
import sys


def alerta(level=10, rule_id="100101", ip="203.0.113.50", descricao="Honeypot SSH: teste", user="root"):
    """Alerta no mesmo formato que o Wazuh grava em alerts.json."""
    return {
        "timestamp": "2026-10-28T22:10:00.000Z",
        "rule": {"id": rule_id, "level": level, "description": descricao},
        "agent": {"name": "wazuh-manager"},
        "data": {"srcip": ip, "user": user},
    }


# ------------------------------------------------------------------ formatação

def test_mensagem_tem_todos_os_campos_de_triagem(dispatcher):
    texto = dispatcher.montar_mensagem(alerta(level=12, rule_id="100104", ip="192.168.15.4", user="root"))

    assert "100104" in texto
    assert "192.168.15.4" in texto
    assert "root" in texto
    assert "wazuh-manager" in texto
    assert "2026-10-28T22:10:00.000Z" in texto
    assert "nível 12" in texto
    assert "CRÍTICO" in texto  # nível >= 12
    assert "Ação sugerida" in texto


def test_mensagem_usa_srcip_como_preferencia(dispatcher):
    alerta_com_dois_campos = alerta(ip="203.0.113.50")
    alerta_com_dois_campos["data"]["src_ip"] = "198.51.100.20"

    texto = dispatcher.montar_mensagem(alerta_com_dois_campos)
    assert "203.0.113.50" in texto
    assert "198.51.100.20" not in texto


def test_mensagem_faz_escape_de_html(dispatcher):
    """Descrição com markup precisa ser escapada: o Telegram usa parse_mode=HTML."""
    texto = dispatcher.montar_mensagem(
        alerta(descricao="<script>alert('x')</script> & <b>admin</b>")
    )
    assert "<script>" not in texto
    assert "&lt;script&gt;" in texto
    assert "&amp;" in texto


def test_mensagem_sobrevive_a_alerta_incompleto(dispatcher):
    """Linha de rotação/versão diferente do Wazuh não pode derrubar o dispatcher."""
    texto = dispatcher.montar_mensagem({})
    assert "desconhecido" in texto
    assert "N/A" in texto
    assert "nível 0" in texto


def test_acao_sugerida_cobre_as_regras_de_nivel_alto(dispatcher):
    padrao = "Triar o alerta e correlacionar com outros eventos."
    for rule_id in ("100101", "100103", "100104", "100105", "100106", "100107", "100108", "100109", "100110"):
        assert dispatcher.acao_sugerida(rule_id) != padrao, f"regra {rule_id} sem ação específica"
    # ID inteiro (como vem do JSON, às vezes) precisa cair na mesma chave.
    assert dispatcher.acao_sugerida(100101) == dispatcher.acao_sugerida("100101")
    assert dispatcher.acao_sugerida("999999") == padrao


def test_nivel_visual_nos_limites(dispatcher):
    assert "CRÍTICO" in dispatcher.nivel_visual(12)
    assert "CRÍTICO" in dispatcher.nivel_visual(16)
    assert "ALTO" in dispatcher.nivel_visual(10)
    assert "ALTO" in dispatcher.nivel_visual(11)
    assert "MÉDIO" in dispatcher.nivel_visual(8)
    assert "MÉDIO" in dispatcher.nivel_visual(9)
    assert "BAIXO" in dispatcher.nivel_visual(7)
    assert "BAIXO" in dispatcher.nivel_visual(0)


# -------------------------------------------------------------------- cooldown

def test_cooldown_bloqueia_repeticao_da_mesma_regra_e_ip(dispatcher):
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=120)

    assert filtro.liberar(alerta()) is True
    assert filtro.liberar(alerta()) is False, "mesma regra+IP dentro do cooldown deve ser suprimida"


def test_cooldown_nao_afeta_regra_ou_ip_diferente(dispatcher):
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=120)

    assert filtro.liberar(alerta(rule_id="100101", ip="203.0.113.50")) is True
    assert filtro.liberar(alerta(rule_id="100104", ip="203.0.113.50")) is True  # outra regra
    assert filtro.liberar(alerta(rule_id="100101", ip="198.51.100.20")) is True  # outro IP


def test_cooldown_libera_depois_do_intervalo(dispatcher, monkeypatch):
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=120)
    agora = [1_000_000.0]
    monkeypatch.setattr(dispatcher.time, "time", lambda: agora[0])

    assert filtro.liberar(alerta()) is True
    agora[0] += 119
    assert filtro.liberar(alerta()) is False
    agora[0] += 2  # passou dos 120s
    assert filtro.liberar(alerta()) is True


def test_cooldown_zero_libera_sempre(dispatcher):
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=0)
    assert filtro.liberar(alerta()) is True
    assert filtro.liberar(alerta()) is True


# ---------------------------------------------------------------- processamento

def test_processar_linha_ignora_json_invalido(dispatcher):
    enviados = []
    dispatcher.enviar_telegram = lambda texto, dry_run=False: enviados.append(texto)
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=0)

    dispatcher.processar_linha('{"rule": {"id": "100101", "level"', filtro)  # truncada
    dispatcher.processar_linha("", filtro)
    dispatcher.processar_linha("isto não é json", filtro)

    assert enviados == []


def test_processar_linha_respeita_min_level(dispatcher, monkeypatch):
    enviados = []
    monkeypatch.setattr(dispatcher, "enviar_telegram", lambda texto, dry_run=False: enviados.append(texto))
    monkeypatch.setenv("MIN_LEVEL", "10")
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=0)

    dispatcher.processar_linha(json.dumps(alerta(level=5, rule_id="100100")), filtro)
    assert enviados == [], "nível 5 não deve ser enviado com MIN_LEVEL=10"

    dispatcher.processar_linha(json.dumps(alerta(level=10, rule_id="100101")), filtro)
    assert len(enviados) == 1
    assert "100101" in enviados[0]


def test_processar_linha_aplica_cooldown_antes_de_enviar(dispatcher, monkeypatch):
    enviados = []
    monkeypatch.setattr(dispatcher, "enviar_telegram", lambda texto, dry_run=False: enviados.append(texto))
    monkeypatch.setenv("MIN_LEVEL", "10")
    filtro = dispatcher.FiltroAntiSpam(cooldown_segundos=120)

    for _ in range(5):
        dispatcher.processar_linha(json.dumps(alerta()), filtro)

    assert len(enviados) == 1, "cinco eventos iguais devem gerar uma única mensagem"


def test_cli_replay_de_alerts_json_em_dry_run(raiz, tmp_path):
    """Ponta a ponta do modo --file usado na documentação para testar sem Telegram."""
    arquivo = tmp_path / "alerts.json"
    alertas = [
        alerta(level=5, rule_id="100100"),   # abaixo do MIN_LEVEL
        alerta(level=10, rule_id="100101"),
        alerta(level=12, rule_id="100104", descricao="Sequência suspeita"),
    ]
    linhas = [json.dumps(a) for a in alertas]
    linhas.insert(1, '{"rule": {"id": "100102", "level": 8}')  # linha truncada
    arquivo.write_text("\n".join(linhas) + "\n", encoding="utf-8")

    ambiente = {
        **os.environ,
        "MIN_LEVEL": "10",
        "COOLDOWN_SECONDS": "120",
        "PYTHONIOENCODING": "utf-8",
    }
    for chave in ("TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"):
        ambiente.pop(chave, None)

    resultado = subprocess.run(
        [
            sys.executable,
            "alerting/webhook_dispatcher.py",
            "--file",
            str(arquivo),
            "--from-start",
            "--exit-on-eof",
            "--dry-run",
        ],
        cwd=raiz,
        env=ambiente,
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
    )

    assert resultado.returncode == 0, resultado.stderr
    assert "regra 100101" in resultado.stdout
    assert "regra 100104" in resultado.stdout
    assert "regra 100100" not in resultado.stdout, "alerta abaixo do nível mínimo não pode ser enviado"
    assert "DRY-RUN" in resultado.stdout
