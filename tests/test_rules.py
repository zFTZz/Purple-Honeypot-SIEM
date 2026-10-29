"""Testes de regressão das regras customizadas do Wazuh.

O que estes testes cobrem e o que não cobrem (importante para não vender
cobertura falsa):

COBRE
  - o contrato do XML: bem formado, IDs únicos na faixa custom, níveis e
    thresholds iguais aos documentados no relatório;
  - a convenção de `pcre2` ancorado em todo campo de texto exato (o bug da §7.1
    item 2, em que `ssh.login` casava `ssh.login_failed`);
  - a estrutura das correlações (`same_source_ip`, `if_matched_sid` existente) e
    a regra de ouro do §7.2: uma única regra de `frequency` por SID base;
  - o comportamento real das regexes contra entradas positivas e negativas.

NÃO COBRE
  - a decisão do `analysisd` em runtime (batching do logcollector, disputa entre
    correlações). Isso só se valida no pipeline real, com `wazuh-logtest` ou com
    eventos de verdade no `alerts.json` — ver §8 do relatório.
"""
import re
import xml.etree.ElementTree as ET

import pytest

# Contrato documentado em docs/RELATORIO.md §5 e no README (tabela de regras).
# Se alguém mudar um nível sem atualizar a documentação, este teste falha.
NIVEIS_ESPERADOS = {
    "100100": 5,
    "100101": 10,
    "100102": 8,
    "100103": 12,
    "100104": 12,
    "100105": 8,
    "100106": 8,
    "100107": 6,
    "100108": 10,
    "100109": 5,
    "100110": 10,
}

# Regras de correlação por contagem: SID base -> (frequency, timeframe).
CORRELACOES_POR_CONTAGEM = {
    "100101": ("5", "120"),   # SSH brute-force
    "100108": ("10", "60"),   # scan HTTP sequencial
    "100110": ("5", "120"),   # FTP brute-force
}

# SIDs base que não podem ter `ignore`: o anti-spam é do dispatcher (§6, decisão 11).
SEM_IGNORE = ("100100", "100101", "100109", "100110")


# Campos de texto exato que precisam de regex ancorada (^...$).
# `user_agent` é lista de ferramentas, `path` é substring de isca e `src_ip` da
# 100103 é prefixo de faixa privada: os três são deliberadamente não ancorados.
CAMPOS_ANCORADOS = {"type", "command", "method"}


@pytest.fixture(scope="module")
def arvore(regras_xml):
    return ET.parse(regras_xml).getroot()


@pytest.fixture(scope="module")
def regras(arvore):
    """Mapa id -> elemento da regra."""
    return {r.get("id"): r for r in arvore.iter("rule")}


def _campo(regra, nome):
    """Devolve o elemento <field name="..."> ou None."""
    for campo in regra.findall("field"):
        if campo.get("name") == nome:
            return campo
    return None


def _padrao(regra, nome):
    campo = _campo(regra, nome)
    return None if campo is None else (campo.text or "")


def test_arquivo_bem_formado_e_dentro_do_grupo(arvore):
    # ET.parse já falha se o XML estiver quebrado; aqui garantimos o grupo esperado,
    # que é o que o Wazuh carrega como conjunto de regras do honeypot.
    assert arvore.tag == "group"
    assert "honeypot" in (arvore.get("name") or "")


def test_onze_regras_com_ids_unicos_na_faixa_custom(regras):
    assert len(regras) == 11, f"esperava 11 regras, encontrei {len(regras)}: {sorted(regras)}"
    # IDs >= 100100 não sobrescrevem o ruleset nativo do Wazuh (decisão 5 da §6).
    for rule_id in regras:
        assert int(rule_id) >= 100100, f"regra {rule_id} invade a faixa nativa do Wazuh"


def test_ids_batem_com_a_tabela_documentada(regras):
    assert sorted(regras) == sorted(NIVEIS_ESPERADOS)


def test_niveis_batem_com_a_documentacao(regras):
    divergentes = {
        rule_id: (int(regra.get("level")), NIVEIS_ESPERADOS[rule_id])
        for rule_id, regra in regras.items()
        if int(regra.get("level")) != NIVEIS_ESPERADOS[rule_id]
    }
    assert not divergentes, f"nível(real) != nível(documentado): {divergentes}"


def test_todas_as_regras_tem_descricao(regras):
    for rule_id, regra in regras.items():
        descricao = (regra.findtext("description") or "").strip()
        assert descricao, f"regra {rule_id} sem <description>"


@pytest.mark.parametrize("rule_id", sorted(NIVEIS_ESPERADOS))
def test_campos_de_texto_exato_sao_pcre2_ancorados(regras, rule_id):
    """Todo <field> de texto exato usa type=pcre2 com ^...$ (convenção do arquivo)."""
    regra = regras[rule_id]
    for campo in regra.findall("field"):
        nome = campo.get("name")
        padrao = campo.text or ""
        assert campo.get("type") == "pcre2", f"{rule_id}: campo {nome} sem type=pcre2"
        if nome not in CAMPOS_ANCORADOS:
            continue
        assert padrao.startswith("^"), f"{rule_id}: regex de {nome} não é ancorada no início"
        assert padrao.endswith("$"), f"{rule_id}: regex de {nome} não é ancorada no fim"


def test_campo_type_ssh_login_nao_casa_login_failed(regras):
    """Regressão do §7.1 item 2: match por substring fazia ssh.login casar ssh.login_failed."""
    padrao = re.compile(_padrao(regras["100103"], "type"))
    assert padrao.search("ssh.login")
    assert not padrao.search("ssh.login_failed")


def test_correlacoes_apontam_para_regras_existentes(regras):
    for rule_id, regra in regras.items():
        for tag in ("if_sid", "if_matched_sid"):
            for referencia in regra.findall(tag):
                sid = (referencia.text or "").strip()
                assert sid in regras, f"{rule_id} referencia {tag}={sid}, que não existe no arquivo"


def test_uma_unica_regra_de_frequency_por_sid_base(regras):
    """Regressão do §7.2: duas regras de frequency na mesma base consomem os eventos.

    Foi exatamente isso que impedia a 100101 de disparar ao vivo quando a 100104
    também tinha `frequency`. Aqui a invariante é verificada estaticamente.
    """
    por_base = {}
    for rule_id, regra in regras.items():
        if regra.get("frequency") is None:
            continue
        base = (regra.findtext("if_matched_sid") or "").strip()
        por_base.setdefault(base, []).append(rule_id)

    conflitos = {base: ids for base, ids in por_base.items() if len(ids) > 1}
    assert not conflitos, f"mais de uma regra de frequency na mesma base: {conflitos}"


@pytest.mark.parametrize("rule_id", sorted(CORRELACOES_POR_CONTAGEM))
def test_thresholds_das_correlacoes_por_contagem(regras, rule_id):
    regra = regras[rule_id]
    frequency, timeframe = CORRELACOES_POR_CONTAGEM[rule_id]
    assert regra.get("frequency") == frequency, f"{rule_id}: frequency divergente"
    assert regra.get("timeframe") == timeframe, f"{rule_id}: timeframe divergente"
    assert regra.find("same_source_ip") is not None


def test_todas_as_correlacoes_usam_same_source_ip(regras):
    correlacionadas = [
        rule_id for rule_id, regra in regras.items() if regra.find("if_matched_sid") is not None
    ]
    assert correlacionadas, "nenhuma regra de correlação encontrada"
    for rule_id in correlacionadas:
        assert regras[rule_id].find("same_source_ip") is not None, (
            f"{rule_id}: correlação sem <same_source_ip /> (same_srcip não funciona com JSON, §5.2)"
        )
    # Nenhuma regra deve voltar para o same_srcip que não disparava.
    for rule_id, regra in regras.items():
        assert regra.find("same_srcip") is None, (
            f"{rule_id}: <same_srcip> não funciona com logs JSON no Wazuh 4.7.2 (§5.2)"
        )


def test_100104_sem_frequency_com_a_sequencia_correta(regras):
    regra = regras["100104"]
    assert regra.get("frequency") is None, "100104 não deve ter frequency (§5.5)"
    assert regra.get("timeframe") == "300"
    assert (regra.findtext("if_sid") or "").strip() == "100102"
    assert (regra.findtext("if_matched_sid") or "").strip() == "100100"
    assert regra.find("same_source_ip") is not None


@pytest.mark.parametrize("rule_id", SEM_IGNORE)
def test_regras_de_falha_nao_usam_ignore(regras, rule_id):
    """O anti-spam fica no dispatcher; `ignore` escondia alertas nos testes (§7.1 item 8)."""
    assert regras[rule_id].get("ignore") is None, f"{rule_id} não deve ter ignore"


def test_100103_usa_negate_e_cobre_apenas_faixas_privadas(regras):
    campo = _campo(regras["100103"], "src_ip")
    assert campo is not None
    assert campo.get("negate") == "yes", "100103 precisa de negate=yes (IP fora das faixas internas)"

    padrao = re.compile(campo.text)
    privados = ["10.0.0.1", "10.255.255.254", "172.16.0.1", "172.31.255.1", "192.168.15.9", "127.0.0.1"]
    publicos = ["8.8.8.8", "203.0.113.30", "11.0.0.1", "172.32.0.1", "172.15.0.1", "192.169.0.1"]

    for ip in privados:
        assert padrao.search(ip), f"{ip} deveria ser tratado como faixa interna"
    for ip in publicos:
        assert not padrao.search(ip), f"{ip} deveria ser tratado como origem externa"


def test_100105_reconhece_user_agents_de_scanner(regras):
    padrao = re.compile(_padrao(regras["100105"], "user_agent"))
    scanners = [
        "sqlmap/1.7.2#stable (https://sqlmap.org)",
        "Mozilla/5.00 (Nikto/2.5.0)",
        "Mozilla/5.0 (compatible; Nmap Scripting Engine)",
        "ffuf/1.5.0",
        "gobuster/3.6",
        "zgrab/0.x",
    ]
    legitimos = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "curl/8.4.0", "python-requests/2.31"]

    for ua in scanners:
        assert padrao.search(ua), f"UA de scanner não reconhecido: {ua}"
    for ua in legitimos:
        assert not padrao.search(ua), f"UA legítimo marcado como scanner: {ua}"


def test_100106_reconhece_iscas_e_traversal(regras):
    padrao = re.compile(_padrao(regras["100106"], "path"))
    suspeitos = ["/.env", "/.env.bak", "/.git/config", "/admin", "/admin/login", "/config.php", "/backup/db.sql", "/../../etc/passwd"]
    legitimos = ["/", "/produtos", "/robots.txt", "/login"]

    for path in suspeitos:
        assert padrao.search(path), f"isca não reconhecida: {path}"
    for path in legitimos:
        assert not padrao.search(path), f"caminho legítimo marcado como isca: {path}"


def test_100102_reconhece_comandos_de_reconhecimento(regras):
    padrao = re.compile(_padrao(regras["100102"], "command"))
    recon = ["id", "whoami", "uname", "uname -a", "cat /etc/passwd", "cat /etc/shadow"]
    outros = ["ls", "pwd", "whoami; id", "cat id_rsa"]

    for comando in recon:
        assert padrao.search(comando), f"comando de recon não reconhecido: {comando}"
    for comando in outros:
        assert not padrao.search(comando), f"comando comum marcado como recon: {comando}"


def test_100107_casa_apenas_post(regras):
    padrao = re.compile(_padrao(regras["100107"], "method"))
    assert padrao.search("POST")
    assert not padrao.search("GET")
    assert not padrao.search("POSTISH")


def test_regra_de_scanner_e_avaliada_antes_das_regras_genericas(regras):
    """O Wazuh dispara a primeira regra que casa: 100105 precisa vir antes de 100106/100107.

    Um scan com User-Agent de ferramenta deve ser atribuído à ferramenta (mais
    informativo) e não a um acesso genérico a isca.
    """
    ordem = list(regras)
    assert ordem.index("100105") < ordem.index("100106")
    assert ordem.index("100105") < ordem.index("100107")
