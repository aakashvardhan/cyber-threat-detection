"""Load the ATT&CK knowledge graph (app/attack_graph.py) into Neo4j for GraphRAG.

The backend also loads it by itself on start when Neo4j is empty or out of date (NEO4J_AUTOLOAD=true);
this script reloads it on demand and, with --check, compares Neo4j with the in-memory graph.

Run from the backend folder, with Neo4j running (docker compose up neo4j) and NEO4J_* set in backend/.env:
    python scripts/load_neo4j.py            # replaces the graph in the database
    python scripts/load_neo4j.py --check    # also compares Neo4j retrieval with the in-memory graph

Every node gets the label :AttackEntity plus its type (:Technique, :Group, ...); relationships keep the ATT&CK
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

def load(session, graph) -> dict:
    from app.attack_graph import load_into_neo4j
    return load_into_neo4j(session, graph)


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
