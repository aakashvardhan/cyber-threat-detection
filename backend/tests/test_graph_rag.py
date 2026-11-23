"""GraphRAG: the ATT&CK knowledge graph, graph-guided retrieval, the Neo4j store and the API."""
import json
import re

import pytest
from fastapi.testclient import TestClient

from app.attack_graph import AttackGraph, Neo4jStore, NetworkXStore
from app.graph_rag import GraphRetriever
from app.knowledge import KnowledgeBase
from app.main import create_app
from conftest import API_KEY, wait_ready

TACTICS = [("reconnaissance", "Reconnaissance", "TA0043"), ("initial-access", "Initial Access", "TA0001"), ("credential-access", "Credential Access", "TA0006"),
           ("discovery", "Discovery", "TA0007"), ("lateral-movement", "Lateral Movement", "TA0008")]


def ref(kind, i):
    return f"{kind}--{i:08d}-0000-0000-0000-000000000000"


def ext(attack_id, path):
    return [{"source_name": "mitre-attack", "external_id": attack_id, "url": f"https://attack.mitre.org/{path}/{attack_id}"}]


def technique(i, tid, name, phase, sub=False):
    return {"type": "attack-pattern", "id": ref("attack-pattern", i), "name": name, "x_mitre_is_subtechnique": sub,
            "description": f"{name} description. (Citation: X)", "external_references": ext(tid, "techniques"),
            "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": phase}]}


def rel(i, src, kind, dst, text=None):
    out = {"type": "relationship", "id": ref("relationship", i), "source_ref": src, "relationship_type": kind,
           "target_ref": dst}
    if text:
        out["description"] = text
    return out


def make_stix(path):
    objs = [{"type": "x-mitre-matrix", "id": ref("x-mitre-matrix", 1), "name": "Enterprise",
             "tactic_refs": [ref("x-mitre-tactic", i) for i in range(len(TACTICS))]}]
    for i, (short, name, tid) in enumerate(TACTICS):
        objs.append({"type": "x-mitre-tactic", "id": ref("x-mitre-tactic", i), "name": name, "x_mitre_shortname": short,
                     "external_references": ext(tid, "tactics")})
    techs = [(1, "T1595", "Active Scanning", "reconnaissance", False), (2, "T1595.002", "Vulnerability Scanning", "reconnaissance", True),
             (3, "T1110", "Brute Force", "credential-access", False), (4, "T1046", "Network Service Discovery", "discovery", False),
             (5, "T1021", "Remote Services", "lateral-movement", False), (6, "T1018", "Remote System Discovery", "discovery", False),
             (7, "T1190", "Exploit Public-Facing Application", "initial-access", False)]
    objs += [technique(*t) for t in techs]
    T = {t[1]: ref("attack-pattern", t[0]) for t in techs}
    groups = [(1, "G0001", "Scanner Group"), (2, "G0002", "Brute Crew"), (3, "G0003", "Quiet Team")]
    objs += [{"type": "intrusion-set", "id": ref("intrusion-set", i), "name": n, "aliases": [n],
              "external_references": ext(g, "groups")} for i, g, n in groups]
    G = {g: ref("intrusion-set", i) for i, g, _ in groups}
    objs.append({"type": "malware", "id": ref("malware", 1), "name": "Hammer", "external_references": ext("S0001", "software")})
    objs.append({"type": "course-of-action", "id": ref("course-of-action", 1), "name": "Password Policies",
                 "external_references": ext("M1027", "mitigations")})
    objs.append({"type": "x-mitre-data-component", "id": ref("x-mitre-data-component", 1), "name": "Network Traffic Flow",
                 "external_references": ext("DC0078", "datacomponents")})
    objs.append({"type": "x-mitre-analytic", "id": ref("x-mitre-analytic", 1), "name": "Analytic 1",
                 "x_mitre_log_source_references": [{"x_mitre_data_component_ref": ref("x-mitre-data-component", 1)}]})
    objs.append({"type": "x-mitre-detection-strategy", "id": ref("x-mitre-detection-strategy", 1), "name": "Detect scans",
                 "x_mitre_analytic_refs": [ref("x-mitre-analytic", 1)], "external_references": ext("DET0001", "detectionstrategies")})
    rels = [(G["G0001"], "uses", T["T1595.002"], "Scanner Group scanned web servers for vulnerabilities."),
            (G["G0001"], "uses", T["T1110"], "Scanner Group guessed SSH passwords."),
            (G["G0002"], "uses", T["T1595"], "Brute Crew swept address ranges."),
            (G["G0002"], "uses", T["T1110"], None), (G["G0002"], "uses", T["T1021"], None),
            (G["G0003"], "uses", T["T1046"], None), (G["G0003"], "uses", T["T1018"], None),
            (G["G0002"], "uses", T["T1190"], "Brute Crew exploited a web server."),
            (ref("malware", 1), "uses", T["T1110"], "Hammer brute forces RDP."),
            (ref("course-of-action", 1), "mitigates", T["T1110"], "Use strong passwords."),
            (ref("x-mitre-detection-strategy", 1), "detects", T["T1595"], None),
            (T["T1595.002"], "subtechnique-of", T["T1595"], None)]
    objs += [rel(i, *r) for i, r in enumerate(rels, start=1)]
    path.write_text(json.dumps({"type": "bundle", "objects": objs}))
    return path


CTI = [{"id": "cti-1", "text": "The group brute forced SSH accounts on exposed servers.",
        "metadata": {"technique_id": "T1110", "technique_ids": ["T1110"], "apt_group": "Scanner Group",
                     "report": "REP1", "report_title": "Report one", "report_url": "https://example.org/r1"}}]


@pytest.fixture
def graph(tmp_path):
    return AttackGraph.from_stix(make_stix(tmp_path / "enterprise-attack.json"), CTI)


def test_graph_has_attack_entities_relations_and_communities(graph):
    stats = graph.stats()
    assert stats["node_types"]["Technique"] == 7 and stats["node_types"]["Group"] == 3
    assert stats["node_types"]["Report"] == 1 and stats["relationship_types"]["DESCRIBES"] == 1
    assert ("R-REP1", "ABOUT", "G0001", {}) in graph.edges
    assert graph.tactic_order == [t[1] for t in TACTICS]
    assert graph.nodes["T1595.002"]["parent"] == "T1595" and graph.nodes["T1110"]["stage"] == 2
    assert graph.users_by_technique()["T1595"] == {"G0001", "G0002"}      # via the sub-technique too
    assert all(graph.nodes[t].get("community") for t in ("T1595", "T1110"))


def test_retrieval_follows_the_graph(graph, tmp_path):
    kb = KnowledgeBase()
    r = GraphRetriever(graph, NetworkXStore(graph), kb).retrieve(
        "T1595", "Reconnaissance", "scan ssh", 5, alternatives=["T1046"],
        history=[{"technique_id": "T1046", "name": "Network Service Discovery", "first_seen": "2025-01-01T00:00:00Z",
                  "target_count": 3}])
    titles = [e["title"] for e in r.evidence]
    assert r.evidence[0]["source"] == "mitre" and r.evidence[0]["ref"] == "T1595"
    who = next(e for e in r.evidence if e["title"].startswith("Who uses"))
    assert "2 actors" in who["text"] and "not attribution" in who["text"]
    nxt = next(e for e in r.evidence if e["title"].startswith("What actors"))
    assert "T1110 Brute Force" in nxt["text"] and "2 (100%)" in nxt["text"]       # both users also brute force
    assert any(t.startswith("Alternative: T1046") for t in titles)
    assert any(t == "Earlier activity from this source" for t in titles)
    assert any(e["source"] == "procedure" and "scanned web servers" in e["text"] for e in r.evidence)
    assert [e["evidence_id"] for e in r.evidence] == [f"E{i}" for i in range(1, len(r.evidence) + 1)]
    g = r.trace["graph"]
    roles = {n["id"]: n["role"] for n in g["nodes"]}
    assert roles["T1595"] == "seed" and roles["G0001"] == "user" and roles["T1110"] == "next"
    assert roles["T1046"] == "alternative" and roles["DC0078"] == "data"
    assert {"source": "G0001", "target": "T1595", "relation": "USES"} in g["edges"]    # sub-technique drawn on the parent
    assert r.trace["retriever"] == "graph" and g["store"] == "networkx"


def test_cti_spans_come_from_report_edges(graph):
    r = GraphRetriever(graph, NetworkXStore(graph), KnowledgeBase()).retrieve("T1110", None, "ssh brute force", 5)
    cti = [e for e in r.evidence if e["source"] == "cti"]
    assert cti and cti[0]["text"].startswith("The group brute forced SSH")
    assert any(n["id"] == "M1027" and n["role"] == "mitigation" for n in r.trace["graph"]["nodes"])


class FakeNeo4j:
    """Answers Neo4jStore's Cypher from the in-memory graph, to test the store's Python side."""

    def __init__(self, graph):
        self.graph = graph

    def session(self, database=None):
        return self

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        g = self.graph
        stored = [(s, r, t, {k: (json.dumps(v) if isinstance(v, list) else v) for k, v in p.items()}) for s, r, t, p in g.edges]
        if "tech.parent IN $seeds" in query:
            ids = {n for n, v in g.nodes.items() if v["type"] == "Technique" and v["parent"] in params["seeds"]}
            return [{"s": s, "rel": r, "t": t, "props": p} for s, r, t, p in stored if s in ids or t in ids]
        if "USES|ATTRIBUTED_TO" in query:
            return [{"s": s, "rel": r, "t": t} for s, r, t, _ in g.edges if s in params["actors"]
                    and (r == "ATTRIBUTED_TO" or (r == "USES" and g.nodes[t]["type"] == "Technique"))]
        if "ABOUT|USES_DATA" in query:
            return [{"s": s, "rel": r, "t": t} for s, r, t, _ in g.edges if s in params["ids"] and r in ("ABOUT", "USES_DATA")]
        if "RETURN e {.*} AS node" in query:
            return [{"node": dict(g.nodes[i])} for i in params["ids"] if i in g.nodes]
        raise AssertionError(f"unexpected query: {query}")


def test_neo4j_store_matches_the_in_memory_store(graph):
    memory, neo = NetworkXStore(graph), Neo4jStore(FakeNeo4j(graph))
    for tid in ("T1595", "T1110", "T1021"):
        a, b = memory.local_subgraph([tid]), neo.local_subgraph([tid])
        assert {(s, r, t) for s, r, t, _ in a.edges} == {(s, r, t) for s, r, t, _ in b.edges}
        assert set(a.nodes) == set(b.nodes)
        ra = GraphRetriever(graph, memory, KnowledgeBase()).retrieve(tid, None, tid, 5)
        rb = GraphRetriever(graph, neo, KnowledgeBase()).retrieve(tid, None, tid, 5)
        assert [e["text"] for e in ra.evidence] == [e["text"] for e in rb.evidence]
        assert rb.trace["graph"]["store"] == "neo4j"


def test_cypher_uses_distinct_variable_names():
    for query in (Neo4jStore.LOCAL, Neo4jStore.ACTORS, Neo4jStore.AROUND, Neo4jStore.NODES):
        bound = set(re.findall(r"\((\w+):", query))
        aliases = set(re.findall(r"AS (\w+)", query))
        assert not bound & aliases, query


def test_incident_api_returns_the_graph_trace(make_settings, tmp_path):
    settings = make_settings(attack_stix=make_stix(tmp_path / "stix.json"), retriever="graph")
    with TestClient(create_app(settings), headers={"X-API-Key": API_KEY}) as client:
        client.post("/detect", json={"reset": True})
        while client.post("/detect", json={}).status_code == 200:
            pass
        incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
        body = wait_ready(client, incident_id)
    trace = body["retrieval_trace"]
    assert trace["retriever"] == "graph" and trace["graph"]["store"] == "networkx"
    assert any(e["source"] == "graph" for e in body["evidence"])
    assert body["explanation"]["status"] == "ready"


def test_vector_retriever_stays_available(make_settings, tmp_path):
    settings = make_settings(attack_stix=make_stix(tmp_path / "stix.json"), retriever="vector")
    with TestClient(create_app(settings), headers={"X-API-Key": API_KEY}) as client:
        client.post("/detect", json={"reset": True})
        while client.post("/detect", json={}).status_code == 200:
            pass
        incident_id = client.get("/incidents").json()["incidents"][0]["incident_id"]
        body = wait_ready(client, incident_id)
    assert body["retrieval_trace"]["retriever"] in ("vector", "token")
    assert body["retrieval_trace"].get("graph") is None
    assert not any(e["source"] == "graph" for e in body["evidence"])


def test_graph_signature_is_stable_and_tracks_changes(tmp_path):
    a = AttackGraph.from_stix(make_stix(tmp_path / "a.json"), CTI)
    b = AttackGraph.from_stix(make_stix(tmp_path / "b.json"), CTI)
    assert a.signature() == b.signature()                 # same input, same graph: no reload
    c = AttackGraph.from_stix(make_stix(tmp_path / "c.json"))   # without the CTI report
    assert c.signature() != a.signature()


class RecordingSession:
    """Records the Cypher that load_into_neo4j sends (no Neo4j needed)."""

    def __init__(self):
        self.calls = []

    def run(self, query, **params):
        self.calls.append((query, params))
        rows = {"deleted": 0, "total": 1}

        class Result:
            def consume(self):
                return None

            def single(self):
                return rows
        return Result()


def test_load_into_neo4j_sends_every_node_edge_and_the_signature(graph):
    from app.attack_graph import load_into_neo4j
    session = RecordingSession()
    load_into_neo4j(session, graph)
    queries = [q for q, _ in session.calls]
    assert any("CREATE CONSTRAINT attack_entity_id" in q for q in queries)
    # only this graph's nodes are deleted, never other data in the database (#60 review)
    deletes = [i for i, q in enumerate(queries) if "DELETE" in q]
    assert all(":AttackEntity" in queries[i] or "GraphMeta" in queries[i] for i in deletes)
    assert not any("(e:Entity)" in q for q in queries)
    # the old signature goes first, the new one only after every node and relationship is written
    drop_meta = next(i for i, q in enumerate(queries) if "GraphMeta" in q and "DELETE" in q)
    set_meta = next(i for i, q in enumerate(queries) if "GraphMeta" in q and "SET m.signature" in q)
    writes = [i for i, q in enumerate(queries) if "MERGE (e:AttackEntity" in q or "MERGE (a)-[r:" in q]
    assert drop_meta < min(deletes + writes) or drop_meta == min(deletes)
    assert set_meta > max(writes)
    sent_nodes = sum(len(p["rows"]) for q, p in session.calls if "MERGE (e:AttackEntity" in q)
    sent_edges = sum(len(p["rows"]) for q, p in session.calls if "MERGE (a)-[r:" in q)
    assert sent_nodes == len(graph.nodes) and sent_edges == len(graph.edges)
    meta = next(p for q, p in session.calls if "GraphMeta" in q and "SET m.signature" in q)
    assert meta["sig"] == graph.signature()
    describes = next(p for q, p in session.calls if "[r:DESCRIBES]" in q)["rows"][0]["props"]
    assert isinstance(describes["chunks"], str)            # lists of dicts are stored as JSON text


def test_signature_changes_with_text_only_updates(graph):
    before = graph.signature()
    node = next(iter(graph.nodes.values()))
    node["name"] = node.get("name", "") + " (renamed)"                    # same IDs and relationships, new text
    assert graph.signature() != before
