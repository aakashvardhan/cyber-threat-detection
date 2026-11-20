"""Load the ATT&CK knowledge graph (app/attack_graph.py) into Neo4j for GraphRAG.

Run from the backend folder, with Neo4j running (docker compose up neo4j) and NEO4J_* set in backend/.env:
    python scripts/load_neo4j.py            # replaces the graph in the database
    python scripts/load_neo4j.py --check    # also compares Neo4j retrieval with the in-memory graph

Every node gets the label :Entity plus its type (:Technique, :Group, ...); relationships keep the ATT&CK
names (USES, MITIGATES, ...). The backend then queries Neo4j when NEO4J_URI is set.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from collections import defaultdict
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "scripts"))

LABELS = {"Technique", "Tactic", "Group", "Software", "Campaign", "Mitigation", "DetectionStrategy",
          "DataComponent", "Report", "Community"}
BATCH = 1000


def batches(rows, size=BATCH):
    for i in range(0, len(rows), size):
        yield rows[i:i + size]


def node_props(node: dict) -> dict:
    """Neo4j properties are primitives or lists of primitives."""
    return {k: v for k, v in node.items() if v is not None and not isinstance(v, dict)}


def edge_props(props: dict) -> dict:
    out = {}
    for k, v in (props or {}).items():
        out[k] = json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v
    return out


def load(session, graph) -> dict:
    session.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE").consume()
    session.run("CREATE INDEX technique_parent IF NOT EXISTS FOR (x:Technique) ON (x.parent)").consume()
    while session.run("MATCH (e:Entity) WITH e LIMIT 5000 DETACH DELETE e RETURN count(*) AS deleted").single()["deleted"]:
        pass
    by_type = defaultdict(list)
    for node in graph.nodes.values():
        by_type[node["type"]].append({"id": node["id"], "props": node_props(node)})
    for label, rows in by_type.items():
        if label not in LABELS:
            raise ValueError(f"unexpected node type {label}")
        for part in batches(rows):
            session.run(f"UNWIND $rows AS row MERGE (e:Entity {{id: row.id}}) SET e += row.props, e:{label}",
                        rows=part).consume()
    by_rel = defaultdict(list)
    for s, rel, t, props in graph.edges:
        by_rel[rel].append({"s": s, "t": t, "props": edge_props(props)})
    for rel, rows in by_rel.items():
        if not rel.replace("_", "").isalnum():
            raise ValueError(f"unexpected relationship type {rel}")
        for part in batches(rows):
            session.run(f"UNWIND $rows AS row MATCH (a:Entity {{id: row.s}}) MATCH (b:Entity {{id: row.t}}) "
                        f"MERGE (a)-[r:{rel}]->(b) SET r += row.props", rows=part).consume()
    nodes = session.run("MATCH (e:Entity) RETURN count(e) AS total").single()["total"]
    rels = session.run("MATCH (:Entity)-[r]->(:Entity) RETURN count(r) AS total").single()["total"]
    return {"nodes": nodes, "relationships": rels}


def check(graph, store, kb, techniques: list[str]) -> bool:
    """Neo4j and the in-memory graph must return the same subgraph and the same evidence."""
    from app.attack_graph import NetworkXStore
    from app.graph_rag import GraphRetriever

    memory = NetworkXStore(graph)
    ok = True
    for tid in techniques:
        a, b = memory.local_subgraph([tid]), store.local_subgraph([tid])
        ea = {(s, r, t) for s, r, t, _ in a.edges}
        eb = {(s, r, t) for s, r, t, _ in b.edges}
        ra = GraphRetriever(graph, memory, kb).retrieve(tid, None, tid, 5)
        rb = GraphRetriever(graph, store, kb).retrieve(tid, None, tid, 5)
        same_evidence = [e["text"] for e in ra.evidence] == [e["text"] for e in rb.evidence]
        line = (f"{tid}: nodes {len(a.nodes)}/{len(b.nodes)}, edges {len(ea)}/{len(eb)}, "
                f"evidence {'same' if same_evidence else 'DIFFERENT'}, Neo4j {rb.trace['latency_ms']} ms")
        if ea != eb or set(a.nodes) != set(b.nodes) or not same_evidence:
            ok = False
            line += f"  <- mismatch: {len(ea - eb)} edges only in memory, {len(eb - ea)} only in Neo4j"
        print(line)
    return ok


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true", help="compare Neo4j retrieval with the in-memory graph")
    parser.add_argument("--techniques", default="T1595,T1110,T1046,T1190,T1048,T1021",
                        help="techniques used by --check")
    args = parser.parse_args()
    from eval_explanations import load_env
    load_env(HERE / ".env")

    from neo4j import GraphDatabase
    from app.attack_graph import AttackGraph, Neo4jStore
    from app.config import Settings
    from app.knowledge import KnowledgeBase

    settings = Settings.from_env()
    if not settings.neo4j_uri:
        sys.exit("Set NEO4J_URI (e.g. bolt://localhost:7687), NEO4J_USER and NEO4J_PASSWORD in backend/.env")
    if settings.attack_stix is None or not settings.attack_stix.exists():
        sys.exit("ATT&CK STIX file not found; set ATTACK_STIX")
    kb = KnowledgeBase.load(settings.knowledge_dir)
    started = time.time()
    graph = AttackGraph.from_stix(settings.attack_stix, kb.chunks.get("cti"))
    print(f"Built the graph in {time.time() - started:.1f}s: {json.dumps(graph.stats())}")
    driver = GraphDatabase.driver(settings.neo4j_uri, auth=(settings.neo4j_user, settings.neo4j_password or ""))
    driver.verify_connectivity()
    started = time.time()
    with driver.session(database=settings.neo4j_database) as session:
        counts = load(session, graph)
    print(f"Loaded into Neo4j in {time.time() - started:.1f}s: {counts}")
    if args.check:
        store = Neo4jStore(driver, settings.neo4j_database)
        ok = check(graph, store, kb, [t.strip() for t in args.techniques.split(",") if t.strip()])
        print("Neo4j matches the in-memory graph." if ok else "Neo4j and the in-memory graph differ (see above).")
        driver.close()
        sys.exit(0 if ok else 1)
    driver.close()


if __name__ == "__main__":
    main()
