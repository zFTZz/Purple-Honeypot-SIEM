"""
Cria o dashboard do Purple Honeypot SIEM no Wazuh Dashboard (OpenSearch Dashboards).

Uso (com o dashboard em https://localhost:5601):
    python siem/create_dashboard.py

O script é idempotente: procura os objetos pelo título e atualiza os existentes.
Não imprime senha. As credenciais padrão do laboratório são admin/admin; para
outro ambiente, use --username/--password ou as variáveis OSD_USER/OSD_PASSWORD.
"""
import argparse
import http.cookiejar
import json
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request

INDEX_TITLE = "wazuh-alerts-*"
INDEX_REF = "kibanaSavedObjectMeta.searchSourceJSON.index"

PIE_TITLE = "Honeypot - alertas por regra"
LINE_TITLE = "Honeypot - alertas ao longo do tempo"
TABLE_TITLE = "Honeypot - top IPs"
COMMAND_TITLE = "Honeypot - comandos executados"
SEARCH_TITLE = "Honeypot - alertas recentes"
DASH_TITLE = "Purple Honeypot SIEM"


def make_opener():
    ctx = ssl._create_unverified_context()
    jar = http.cookiejar.CookieJar()
    return urllib.request.build_opener(
        urllib.request.HTTPSHandler(context=ctx),
        urllib.request.HTTPCookieProcessor(jar),
    )


def request_json(opener, method, url, body=None, base_headers=None):
    headers = {"Accept": "application/json", "osd-xsrf": "true"}
    if base_headers:
        headers.update(base_headers)
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with opener.open(req, timeout=30) as resp:
            raw = resp.read().decode("utf-8")
            return resp.status, json.loads(raw) if raw else {}
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"{method} {url} -> HTTP {exc.code}: {raw}") from exc


def login(opener, base, username, password):
    status, body = request_json(
        opener,
        "POST",
        f"{base}/auth/login",
        {"username": username, "password": password},
        {"Content-Type": "application/json"},
    )
    if status != 200:
        raise RuntimeError(f"login falhou: HTTP {status} {body}")
    print(f"[+] Login OK como {body.get('username', username)}")


def find_by_title(opener, base, obj_type, title):
    query = urllib.parse.urlencode({"type": obj_type, "search": title, "per_page": 50})
    _, body = request_json(opener, "GET", f"{base}/api/saved_objects/_find?{query}")
    for obj in body.get("saved_objects", []):
        if obj.get("attributes", {}).get("title") == title:
            return obj
    return None


def upsert(opener, base, obj_type, title, attributes, references=None):
    existing = find_by_title(opener, base, obj_type, title)
    payload = {"attributes": attributes, "references": references or []}
    if existing:
        obj_id = existing["id"]
        request_json(opener, "PUT", f"{base}/api/saved_objects/{obj_type}/{obj_id}", payload)
        print(f"[=] {obj_type}: {title} (atualizado)")
        return obj_id
    _, body = request_json(opener, "POST", f"{base}/api/saved_objects/{obj_type}", payload)
    obj_id = body["id"]
    print(f"[+] {obj_type}: {title} ({obj_id})")
    return obj_id


def search_source():
    return json.dumps(
        {
            "query": {"query": "", "language": "kuery"},
            "filter": [],
            "indexRefName": INDEX_REF,
        },
        ensure_ascii=False,
    )


def index_ref(index_id):
    return [{"name": INDEX_REF, "type": "index-pattern", "id": index_id}]


def pie_vis():
    vis = {
        "title": PIE_TITLE,
        "type": "pie",
        "params": {
            "type": "pie",
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "isDonut": True,
            "labels": {"show": False, "values": True, "last_level": True, "truncate": 100},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": "rule.id",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "otherBucketLabel": "Outros",
                    "missingBucket": False,
                    "missingBucketLabel": "Sem valor",
                },
            },
        ],
    }
    return {
        "title": PIE_TITLE,
        "visState": json.dumps(vis, ensure_ascii=False),
        "uiStateJSON": "{}",
        "description": "Quantidade de alertas por regra custom do honeypot.",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    }


def line_vis():
    vis = {
        "title": LINE_TITLE,
        "type": "line",
        "params": {
            "type": "line",
            "grid": {"categoryLines": False},
            "categoryAxes": [
                {
                    "id": "CategoryAxis-1",
                    "type": "category",
                    "position": "bottom",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear"},
                    "labels": {"show": True, "filter": True, "truncate": 100},
                    "title": {},
                }
            ],
            "valueAxes": [
                {
                    "id": "ValueAxis-1",
                    "name": "LeftAxis-1",
                    "type": "value",
                    "position": "left",
                    "show": True,
                    "style": {},
                    "scale": {"type": "linear", "mode": "normal"},
                    "labels": {"show": True, "rotate": 0, "filter": False, "truncate": 100},
                    "title": {"text": "Alertas"},
                }
            ],
            "seriesParams": [
                {
                    "show": True,
                    "type": "line",
                    "mode": "normal",
                    "dataLabel": "Contagem",
                    "valueAxis": "ValueAxis-1",
                    "drawLinesBetweenPoints": True,
                    "lineWidth": 2,
                    "showCircles": True,
                }
            ],
            "addTooltip": True,
            "addLegend": True,
            "legendPosition": "right",
            "times": [],
            "addTimeMarker": False,
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "date_histogram",
                "schema": "segment",
                "params": {
                    "field": "@timestamp",
                    "timeRange": {"from": "now-24h", "to": "now"},
                    "useNormalizedEsInterval": True,
                    "scaleMetricValues": False,
                    "interval": "auto",
                    "drop_partials": False,
                    "min_doc_count": 1,
                    "extended_bounds": {},
                },
            },
            {
                "id": "3",
                "enabled": True,
                "type": "terms",
                "schema": "group",
                "params": {
                    "field": "rule.id",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 5,
                    "otherBucket": False,
                    "otherBucketLabel": "Outros",
                    "missingBucket": False,
                    "missingBucketLabel": "Sem valor",
                },
            },
        ],
    }
    return {
        "title": LINE_TITLE,
        "visState": json.dumps(vis, ensure_ascii=False),
        "uiStateJSON": "{}",
        "description": "Volume de alertas ao longo do tempo, separado por regra.",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    }


def table_vis():
    vis = {
        "title": TABLE_TITLE,
        "type": "table",
        "params": {
            "perPage": 10,
            "showPartialRows": False,
            "showMetricsAtAllLevels": False,
            "sort": {"columnIndex": None, "direction": None},
            "showTotal": False,
            "totalFunc": "sum",
            "percentageCol": "",
            "dimensions": {"metrics": [], "buckets": []},
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "bucket",
                "params": {
                    "field": "data.srcip",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 10,
                    "otherBucket": False,
                    "otherBucketLabel": "Outros",
                    "missingBucket": False,
                    "missingBucketLabel": "Sem valor",
                },
            },
        ],
    }
    return {
        "title": TABLE_TITLE,
        "visState": json.dumps(vis, ensure_ascii=False),
        "uiStateJSON": "{}",
        "description": "IPs que mais geraram alertas no honeypot.",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    }


def command_vis():
    vis = {
        "title": COMMAND_TITLE,
        "type": "tagcloud",
        "params": {
            "scale": "linear",
            "orientation": "single",
            "minFontSize": 18,
            "maxFontSize": 72,
            "showLabel": True,
            "metric": {"type": "count", "id": "1"},
            "bucket": {
                "type": "terms",
                "id": "2",
                "field": "data.command",
                "size": 20,
                "order": "desc",
                "orderBy": "1",
            },
        },
        "aggs": [
            {"id": "1", "enabled": True, "type": "count", "schema": "metric", "params": {}},
            {
                "id": "2",
                "enabled": True,
                "type": "terms",
                "schema": "segment",
                "params": {
                    "field": "data.command",
                    "orderBy": "1",
                    "order": "desc",
                    "size": 20,
                    "otherBucket": False,
                    "otherBucketLabel": "Outros",
                    "missingBucket": False,
                    "missingBucketLabel": "Sem valor",
                },
            },
        ],
    }
    return {
        "title": COMMAND_TITLE,
        "visState": json.dumps(vis, ensure_ascii=False),
        "uiStateJSON": "{}",
        "description": "Comandos de reconhecimento mais executados no honeypot.",
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    }


def recent_search():
    return {
        "title": SEARCH_TITLE,
        "description": "Últimos alertas com regra, IP, usuário e comando.",
        "columns": ["@timestamp", "rule.id", "rule.level", "rule.description", "data.srcip", "data.user", "data.command"],
        "sort": [["@timestamp", "desc"]],
        "version": 1,
        "kibanaSavedObjectMeta": {"searchSourceJSON": search_source()},
    }


def dashboard_obj(panel_ids):
    panels = []
    refs = []
    layout = [
        (0, 0, 24, 15, "pie"),
        (24, 0, 24, 15, "line"),
        (0, 15, 24, 15, "table"),
        (24, 15, 24, 15, "search"),
        (0, 30, 48, 15, "command"),
    ]
    for i, (x, y, w, h, kind) in enumerate(layout):
        panel_index = str(i + 1)
        ref_name = f"panel_{i}"
        panels.append(
            {
                "version": "2.8.0",
                "gridData": {"x": x, "y": y, "w": w, "h": h, "i": panel_index},
                "panelIndex": panel_index,
                "embeddableConfig": {},
                "panelRefName": ref_name,
            }
        )
        panel_type = "search" if kind == "search" else "visualization"
        refs.append({"name": ref_name, "type": panel_type, "id": panel_ids[kind]})
    attributes = {
        "title": DASH_TITLE,
        "description": "Visão do honeypot SSH/HTTP/FTP: regras, volume, IPs, comandos e alertas recentes.",
        "panelsJSON": json.dumps(panels, ensure_ascii=False),
        "optionsJSON": json.dumps({"useMargins": True, "syncColors": False, "hidePanelTitles": False}),
        "version": 1,
        "timeRestore": True,
        "timeFrom": "now-24h",
        "timeTo": "now",
        "kibanaSavedObjectMeta": {
            "searchSourceJSON": json.dumps({"query": {"query": "", "language": "kuery"}, "filter": []})
        },
    }
    return attributes, refs


def main():
    parser = argparse.ArgumentParser(description="Cria/atualiza o dashboard do Purple Honeypot SIEM.")
    parser.add_argument("--url", default=os.getenv("OSD_URL", "https://localhost:5601"))
    parser.add_argument("--username", default=os.getenv("OSD_USER", "admin"))
    parser.add_argument("--password", default=os.getenv("OSD_PASSWORD", "admin"))
    args = parser.parse_args()
    base = args.url.rstrip("/")
    opener = make_opener()

    print(f"[*] Dashboard: {base}")
    login(opener, base, args.username, args.password)

    index_obj = find_by_title(opener, base, "index-pattern", INDEX_TITLE)
    if index_obj:
        index_id = index_obj["id"]
        print(f"[=] index-pattern: {INDEX_TITLE} ({index_id})")
    else:
        _, body = request_json(
            opener,
            "POST",
            f"{base}/api/saved_objects/index-pattern",
            {"attributes": {"title": INDEX_TITLE, "timeFieldName": "@timestamp"}},
        )
        index_id = body["id"]
        print(f"[+] index-pattern: {INDEX_TITLE} ({index_id})")

    refs = index_ref(index_id)
    pie_id = upsert(opener, base, "visualization", PIE_TITLE, pie_vis(), refs)
    line_id = upsert(opener, base, "visualization", LINE_TITLE, line_vis(), refs)
    table_id = upsert(opener, base, "visualization", TABLE_TITLE, table_vis(), refs)
    command_id = upsert(opener, base, "visualization", COMMAND_TITLE, command_vis(), refs)
    search_id = upsert(opener, base, "search", SEARCH_TITLE, recent_search(), refs)
    dash_attrs, dash_refs = dashboard_obj(
        {"pie": pie_id, "line": line_id, "table": table_id, "command": command_id, "search": search_id}
    )
    dash_id = upsert(opener, base, "dashboard", DASH_TITLE, dash_attrs, dash_refs)
    print(f"[+] Dashboard pronto: {base}/app/dashboards#/view/{dash_id}?_g=(time:(from:now-24h,to:now))")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
