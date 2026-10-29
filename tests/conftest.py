"""Fixtures compartilhadas da suíte de testes do Purple Honeypot SIEM.

Nada aqui sobe Docker nem fala com o Wazuh: os testes rodam em qualquer máquina
com Python e as dependências de `requirements.txt`.
"""
import importlib.util
import json
import pathlib
import sys
import time

import pytest

RAIZ = pathlib.Path(__file__).resolve().parent.parent


def _carregar_modulo(nome, caminho_relativo):
    """Importa um script do repositório pelo caminho, sem transformá-lo em pacote.

    Os honeypots e o dispatcher são scripts soltos (não um pacote instalável), e
    vários nomes de módulo colidem (todos têm `gravar_log`, por exemplo). Carregar
    por caminho mantém cada um isolado no seu próprio namespace.
    """
    caminho = RAIZ / caminho_relativo
    spec = importlib.util.spec_from_file_location(nome, caminho)
    modulo = importlib.util.module_from_spec(spec)
    sys.modules[nome] = modulo
    spec.loader.exec_module(modulo)
    return modulo


@pytest.fixture(scope="session")
def raiz():
    return RAIZ


@pytest.fixture(scope="session")
def regras_xml(raiz):
    return raiz / "siem" / "custom_rules" / "bruteforce_custom.xml"


@pytest.fixture
def carregar():
    """Fábrica de import por caminho (ver `_carregar_modulo`)."""
    return _carregar_modulo


@pytest.fixture
def ssh_honeypot(carregar):
    return carregar("ssh_honeypot_teste", "honeypot/ssh_honeypot.py")


@pytest.fixture
def http_honeypot(carregar):
    return carregar("http_honeypot_teste", "honeypot/http_honeypot.py")


@pytest.fixture
def ftp_honeypot(carregar):
    return carregar("ftp_honeypot_teste", "honeypot/ftp_honeypot.py")


@pytest.fixture
def dispatcher(carregar):
    return carregar("webhook_dispatcher_teste", "alerting/webhook_dispatcher.py")


def ler_json_lines(caminho):
    """Lê um log JSON lines e devolve a lista de eventos."""
    caminho = pathlib.Path(caminho)
    if not caminho.exists():
        return []
    eventos = []
    for linha in caminho.read_text(encoding="utf-8").splitlines():
        linha = linha.strip()
        if linha:
            eventos.append(json.loads(linha))
    return eventos


def esperar(condicao, timeout=10.0, intervalo=0.05):
    """Espera até a condição ser verdadeira; falha com mensagem clara no timeout.

    Os honeypots gravam em thread separada, então o teste precisa esperar o
    evento aparecer no log em vez de assumir que ele já está lá.
    """
    limite = time.time() + timeout
    while time.time() < limite:
        if condicao():
            return True
        time.sleep(intervalo)
    return False


@pytest.fixture
def esperar_eventos():
    return esperar


@pytest.fixture
def ler_log():
    return ler_json_lines
