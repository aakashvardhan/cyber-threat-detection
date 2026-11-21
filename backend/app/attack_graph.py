"""ATT&CK knowledge graph for GraphRAG.

Indexing (Peng et al. 2024, "graph-based indexing"): the graph is built from the MITRE ATT&CK STIX bundle,
an expert-curated knowledge graph, instead of extracting entities with an LLM:

  nodes  Technique, Tactic, Group, Software, Campaign, Mitigation, DetectionStrategy, DataComponent,
         Report (CTI-HAL threat reports)
  edges  Group/Software/Campaign -USES-> Technique      (text: the ATT&CK procedure example)
         Group/Campaign -USES-> Software, Campaign -ATTRIBUTED_TO-> Group
         Mitigation -MITIGATES-> Technique, DetectionStrategy -DETECTS-> Technique,
         DetectionStrategy -USES_DATA-> DataComponent, Technique -SUBTECHNIQUE_OF-> Technique,
         Technique -IN_TACTIC-> Tactic, Report -DESCRIBES-> Technique (text: CTI-HAL spans),
         Report -ABOUT-> Group

Communities (Edge et al. 2024, Microsoft GraphRAG): parent techniques are linked by how many actors use
both; Louvain communities over that co-use graph get a summary each ("techniques that are used together").

Two stores serve the same graph: NetworkXStore (in memory, built at start-up) and Neo4jStore (Cypher, filled
by scripts/load_neo4j.py). Both return the same local subgraph, so retrieval (app/graph_rag.py) is identical.
"""
from __future__ import annotations

import json
import logging
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path

log = logging.getLogger(__name__)

TYPE_OF = {"attack-pattern": "Technique", "x-mitre-tactic": "Tactic", "intrusion-set": "Group", "malware": "Software",
           "tool": "Software", "campaign": "Campaign", "course-of-action": "Mitigation",
           "x-mitre-detection-strategy": "DetectionStrategy", "x-mitre-data-component": "DataComponent"}
ACTOR_TYPES = ("Group", "Software", "Campaign")
# CTI-HAL group names -> ATT&CK group IDs where the alias lists do not match after normalising
CTI_GROUP_IDS = {"SANDWORM": "G0034", "CARBANAK": "G0008", "WIZARDSPIDER": "G0102", "OILRIG": "G0049"}


def clean(text: str, limit: int | None = None) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)          # ATT&CK markdown links -> link text
    text = re.sub(r"<code>|</code>", "", text)
    text = re.sub(r"\s+", " ", text).strip()
    if limit and len(text) > limit:
        text = text[: limit - 1].rsplit(" ", 1)[0] + "…"
    return text


def _norm(name: str) -> str:
    return re.sub(r"[^A-Z0-9]", "", (name or "").upper())


def parent_of(technique_id: str | None) -> str | None:
    return technique_id.split(".")[0] if technique_id else None


@dataclass
class AttackGraph:
    nodes: dict[str, dict] = field(default_factory=dict)           # id -> {id, type, name, ...}
    edges: list[tuple[str, str, str, dict]] = field(default_factory=list)   # (source, REL, target, props)
    tactic_order: list[str] = field(default_factory=list)           # tactic names in kill-chain order
    communities: dict[int, dict] = field(default_factory=dict)      # id -> {id, size, summary, techniques, ...}
    version: str | None = None

    # ----- build -----
    @classmethod
    def from_stix(cls, stix_path: Path, cti_chunks: list[dict] | None = None) -> "AttackGraph":
        bundle = json.loads(Path(stix_path).read_text(encoding="utf-8"))
        raw = bundle["objects"]
        by_ref = {o["id"]: o for o in raw}
        live = [o for o in raw if not o.get("revoked") and not o.get("x_mitre_deprecated")]
        g = cls()

        def ext(o):
            for r in o.get("external_references", []):
                if r.get("source_name") == "mitre-attack" and r.get("external_id"):
                    return r["external_id"], r.get("url")
            return None, None

        ids: dict[str, str] = {}
        shortnames: dict[str, str] = {}
        for o in live:
            kind = TYPE_OF.get(o["type"])
            if not kind:
                continue
            attack_id, url = ext(o)
            if not attack_id:
                continue
            ids[o["id"]] = attack_id
            node = {"id": attack_id, "type": kind, "name": o.get("name", attack_id), "url": url,
                    "description": clean(o.get("description", ""), 600)}
            if kind == "Tactic":
                shortnames[o["x_mitre_shortname"]] = attack_id
            if kind == "Technique":
                node["parent"] = attack_id.split(".")[0]
                node["is_subtechnique"] = bool(o.get("x_mitre_is_subtechnique"))
                node["phases"] = [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                  if p.get("kill_chain_name") == "mitre-attack"]
            if kind in ("Group", "Campaign", "Software"):
                node["aliases"] = [a for a in o.get("aliases", o.get("x_mitre_aliases", [])) if a != node["name"]][:8]
            g.nodes[attack_id] = node
        matrix = next((o for o in live if o["type"] == "x-mitre-matrix"), None)
        order = [by_ref[t]["x_mitre_shortname"] for t in (matrix or {}).get("tactic_refs", []) if t in by_ref]
        g.tactic_order = [g.nodes[shortnames[s]]["name"] for s in order if s in shortnames]
        rank = {s: i for i, s in enumerate(order)}
        for node in g.nodes.values():
            if node["type"] == "Technique":
                phases = sorted(node.pop("phases"), key=lambda s: rank.get(s, 99))
                node["tactics"] = [g.nodes[shortnames[p]]["name"] for p in phases if p in shortnames]
                node["stage"] = rank.get(phases[0], 99) if phases else 99      # earliest kill-chain stage
                for p in phases:
                    if p in shortnames:
                        g.edges.append((node["id"], "IN_TACTIC", shortnames[p], {}))
            elif node["type"] == "Tactic":
                node["stage"] = g.tactic_order.index(node["name"]) if node["name"] in g.tactic_order else 99

        for o in live:
            if o["type"] == "relationship":
                s, t = ids.get(o["source_ref"]), ids.get(o["target_ref"])
                rel = o["relationship_type"]
                if not s or not t or rel == "revoked-by":
                    continue
                props = {"text": clean(o.get("description", ""), 500)} if o.get("description") else {}
                g.edges.append((s, rel.upper().replace("-", "_"), t, props))
            elif o["type"] == "x-mitre-detection-strategy":       # strategy -> analytics -> data components
                s = ids.get(o["id"])
                components = set()
                for a in o.get("x_mitre_analytic_refs", []):
                    for ref in by_ref.get(a, {}).get("x_mitre_log_source_references", []):
                        if ids.get(ref.get("x_mitre_data_component_ref")):
                            components.add(ids[ref["x_mitre_data_component_ref"]])
                for c in sorted(components):
                    g.edges.append((s, "USES_DATA", c, {}))
        g.version = next((o.get("x_mitre_version") for o in raw if o["type"] == "x-mitre-collection"), None)
        if cti_chunks:
            g.add_reports(cti_chunks)
        g.build_communities()
        log.info("ATT&CK graph: %d nodes, %d edges, %d communities", len(g.nodes), len(g.edges), len(g.communities))
        return g

    def add_reports(self, chunks: list[dict]) -> None:
        """CTI-HAL: one Report node per report; its annotated spans become DESCRIBES edges to techniques."""
        alias = {}
        for node in self.nodes.values():
            if node["type"] == "Group":
                for name in [node["name"], *node.get("aliases", [])]:
                    alias.setdefault(_norm(name), node["id"])
        spans: dict[tuple[str, str], list[dict]] = defaultdict(list)
        for c in chunks:
            m = c.get("metadata", {})
            report = m.get("report")
            tid = m.get("technique_id") or (m.get("technique_ids") or [None])[0]
            if not report or not tid:
                continue
            rid = f"R-{report}"
            if rid not in self.nodes:
                self.nodes[rid] = {"id": rid, "type": "Report", "name": m.get("report_title") or report,
                                   "url": m.get("report_url"), "description": "", "apt_group": m.get("apt_group")}
                group = CTI_GROUP_IDS.get(_norm(m.get("apt_group"))) or alias.get(_norm(m.get("apt_group")))
                if group in self.nodes:
                    self.edges.append((rid, "ABOUT", group, {}))
            target = tid if tid in self.nodes else parent_of(tid)
            if target in self.nodes:
                spans[(rid, target)].append({"id": c.get("id"), "text": clean(c.get("text", ""), 400)})
        for (rid, tid), items in spans.items():
            self.edges.append((rid, "DESCRIBES", tid, {"chunks": items[:12]}))

    # ----- communities (Microsoft GraphRAG idea, on the technique co-use graph) -----
    def build_communities(self, seed: int = 42, resolution: float = 1.5) -> None:
        import networkx as nx

        users = self.users_by_technique()
        co = nx.Graph()
        parents = [n for n, v in self.nodes.items() if v["type"] == "Technique" and not v.get("is_subtechnique")]
        co.add_nodes_from(parents)
        by_actor: dict[str, set[str]] = defaultdict(set)
        for tid, actors in users.items():
            for a in actors:
                by_actor[a].add(tid)
        for actor, techs in by_actor.items():
            techs = sorted(techs)
            w = 1.0 / math.log2(2 + len(techs))           # an actor that uses everything says little
            for i, a in enumerate(techs):
                for b in techs[i + 1:]:
                    co.add_edge(a, b, weight=co.get_edge_data(a, b, {"weight": 0})["weight"] + w)
        for a, b, data in co.edges(data=True):              # normalise, so popular techniques do not absorb the rest
            data["weight"] /= math.sqrt(len(users[a]) * len(users[b]))
        # Louvain (networkx); Microsoft GraphRAG uses Leiden, a refinement of the same modularity method
        parts = nx.community.louvain_communities(co, weight="weight", seed=seed, resolution=resolution)
        parts = sorted((p for p in parts if len(p) > 1), key=len, reverse=True)
        total = len(by_actor) or 1
        for nid, node in self.nodes.items():                # how common a technique is among all actors
            if node["type"] == "Technique":
                node["n_users"] = len(users.get(node["parent"], ()))
                node["prevalence"] = round(node["n_users"] / total, 4)
        self.edges = [e for e in self.edges if e[1] != "IN_COMMUNITY"]
        self.nodes = {k: v for k, v in self.nodes.items() if v["type"] != "Community"}
        self.communities = {}
        for i, members in enumerate(parts, start=1):
            summary = self._summarise(i, members, users)
            self.communities[i] = summary
            cid = f"COM-{i}"
            self.nodes[cid] = {"id": cid, "type": "Community", "name": f"Community {i}", "url": None,
                               "description": summary["summary"], "size": summary["size"],
                               "tactics": summary["tactics"], "top_groups": summary["top_groups"],
                               "top_techniques": summary["top_techniques"]}
            for t in members:
                self.nodes[t]["community"] = i
                self.edges.append((t, "IN_COMMUNITY", cid, {}))

    def _summarise(self, cid: int, members: set[str], users: dict[str, set[str]]) -> dict:
        tactic_count = Counter(t for m in members for t in self.nodes[m].get("tactics", [])[:1])
        top_tech = sorted(members, key=lambda m: -len(users.get(m, ())))[:5]
        groups = Counter(a for m in members for a in users.get(m, ()) if self.nodes[a]["type"] == "Group")
        top_groups = [self.nodes[g]["name"] for g, _ in groups.most_common(4)]
        tactics = [t for t, _ in tactic_count.most_common(3)]
        summary = (f"A cluster of {len(members)} techniques that the same actors tend to use together, mostly "
                   f"{', '.join(tactics)}. Its most used techniques are "
                   + ", ".join(f"{t} {self.nodes[t]['name']}" for t in top_tech)
                   + (f"; groups that use many of them include {', '.join(top_groups)}." if top_groups else "."))
        return {"id": cid, "size": len(members), "tactics": tactics, "top_techniques": top_tech,
                "top_groups": top_groups, "summary": summary, "techniques": sorted(members)}

    # ----- helpers shared by the stores -----
    def users_by_technique(self) -> dict[str, set[str]]:
        """Parent technique -> actors (groups, software, campaigns) that use it or one of its sub-techniques."""
        out: dict[str, set[str]] = defaultdict(set)
        for s, rel, t, _ in self.edges:
            if rel == "USES" and self.nodes.get(t, {}).get("type") == "Technique" and self.nodes[s]["type"] in ACTOR_TYPES:
                out[self.nodes[t]["parent"]].add(s)
        return out

    def signature(self) -> str:
        """Changes when the STIX file, the CTI spans or the build code change the graph."""
        import hashlib
        h = hashlib.sha1()
        for s, rel, t, _ in sorted(self.edges, key=lambda e: (e[0], e[1], e[2])):
            h.update(f"{s}|{rel}|{t};".encode())
        h.update(str(sorted(self.communities)).encode())
        return h.hexdigest()

    def stats(self) -> dict:
        types = Counter(v["type"] for v in self.nodes.values())
        rels = Counter(rel for _, rel, _, _ in self.edges)
        return {"nodes": len(self.nodes), "edges": len(self.edges), "node_types": dict(types),
                "relationship_types": dict(rels), "communities": len(self.communities), "attack_version": self.version}


# ----- stores: both answer local_subgraph(seeds) with the same structure -----
def _dedupe(edges: list[tuple[str, str, str, dict]]) -> list[tuple[str, str, str, dict]]:
    """One edge per (source, relation, target), keeping the copy that carries text."""
    out: dict[tuple[str, str, str], tuple[str, str, str, dict]] = {}
    for s, r, t, p in edges:
        if (s, r, t) not in out or (p and not out[(s, r, t)][3]):
            out[(s, r, t)] = (s, r, t, p)
    return list(out.values())


@dataclass
class Subgraph:
    nodes: dict[str, dict]
    edges: list[tuple[str, str, str, dict]]
    store: str

    def out(self, node: str, rel: str) -> list[tuple[str, dict]]:
        return [(t, p) for s, r, t, p in self.edges if s == node and r == rel]

    def into(self, node: str, rel: str) -> list[tuple[str, dict]]:
        return [(s, p) for s, r, t, p in self.edges if t == node and r == rel]


class NetworkXStore:
    name = "networkx"

    def __init__(self, graph: AttackGraph):
        import networkx as nx

        self.graph = graph
        self.g = nx.MultiDiGraph()
        for nid, props in graph.nodes.items():
            self.g.add_node(nid, **props)
        for s, rel, t, props in graph.edges:
            self.g.add_edge(s, t, key=rel, rel=rel, **props)
        self.parent_ids: dict[str, list[str]] = defaultdict(list)       # parent -> itself + sub-techniques
        for nid, v in graph.nodes.items():
            if v["type"] == "Technique":
                self.parent_ids[v["parent"]].append(nid)

    def _edges(self, node: str) -> list[tuple[str, str, str, dict]]:
        out = []
        for s, t, data in list(self.g.in_edges(node, data=True)) + list(self.g.out_edges(node, data=True)):
            props = {k: v for k, v in data.items() if k != "rel"}
            out.append((s, data["rel"], t, props))
        return out

    def local_subgraph(self, seeds: list[str]) -> Subgraph:
        """Seeds (parent technique IDs) and everything one hop away; the seeds' users and *their* techniques."""
        edges: list[tuple[str, str, str, dict]] = []
        for seed in seeds:
            for tid in self.parent_ids.get(seed, []):
                edges += self._edges(tid)
        actors = {s for s, rel, t, _ in edges if rel == "USES" and self.g.nodes[s]["type"] in ACTOR_TYPES}
        reports = {s for s, rel, _, _ in edges if rel == "DESCRIBES"}
        detection = {s for s, rel, _, _ in edges if rel == "DETECTS"}
        for a in actors:
            edges += [(a, "USES", t, {}) for _, t, d in self.g.out_edges(a, data=True)
                      if d["rel"] == "USES" and self.g.nodes[t]["type"] == "Technique"]
            edges += [(a, d["rel"], t, {}) for _, t, d in self.g.out_edges(a, data=True) if d["rel"] == "ATTRIBUTED_TO"]
        for r in reports:
            edges += [(r, "ABOUT", t, {}) for _, t, d in self.g.out_edges(r, data=True) if d["rel"] == "ABOUT"]
        for d_id in detection:
            edges += [(d_id, "USES_DATA", t, {}) for _, t, d in self.g.out_edges(d_id, data=True) if d["rel"] == "USES_DATA"]
        unique = _dedupe(edges)
        ids = {x for s, _, t, _ in unique for x in (s, t)} | set(seeds)
        ids |= {i.split(".")[0] for i in ids if re.match(r"T\d+\.\d+$", i)}     # parents of sub-techniques
        nodes = {i: dict(self.g.nodes[i]) for i in ids if i in self.g.nodes}
        return Subgraph(nodes, unique, self.name)

    def users(self, technique_id: str) -> set[str]:
        out = set()
        for tid in self.parent_ids.get(parent_of(technique_id) or "", []):
            out |= {s for s, _, d in self.g.in_edges(tid, data=True)
                    if d["rel"] == "USES" and self.g.nodes[s]["type"] in ACTOR_TYPES}
        return out


NEO4J_LABELS = {"Technique", "Tactic", "Group", "Software", "Campaign", "Mitigation", "DetectionStrategy",
                "DataComponent", "Report", "Community"}


def load_into_neo4j(session, graph: AttackGraph, batch: int = 1000) -> dict:
    """Replace the ATT&CK graph in Neo4j. Every node is :Entity plus its type; a :GraphMeta node keeps the signature."""
    session.run("CREATE CONSTRAINT entity_id IF NOT EXISTS FOR (e:Entity) REQUIRE e.id IS UNIQUE").consume()
    session.run("CREATE INDEX technique_parent IF NOT EXISTS FOR (x:Technique) ON (x.parent)").consume()
    while session.run("MATCH (e:Entity) WITH e LIMIT 5000 DETACH DELETE e RETURN count(*) AS deleted").single()["deleted"]:
        pass
    by_type: dict[str, list[dict]] = defaultdict(list)
    for node in graph.nodes.values():
        props = {k: v for k, v in node.items() if v is not None and not isinstance(v, dict)}
        by_type[node["type"]].append({"id": node["id"], "props": props})
    for label, rows in by_type.items():
        if label not in NEO4J_LABELS:
            raise ValueError(f"unexpected node type {label}")
        for i in range(0, len(rows), batch):
            session.run(f"UNWIND $rows AS row MERGE (e:Entity {{id: row.id}}) SET e += row.props, e:{label}",
                        rows=rows[i:i + batch]).consume()
    by_rel: dict[str, list[dict]] = defaultdict(list)
    for s, rel, t, props in graph.edges:
        by_rel[rel].append({"s": s, "t": t, "props": {k: (json.dumps(v, ensure_ascii=False) if isinstance(v, (list, dict)) else v)
                                                      for k, v in (props or {}).items()}})
    for rel, rows in by_rel.items():
        if not rel.replace("_", "").isalnum():
            raise ValueError(f"unexpected relationship type {rel}")
        for i in range(0, len(rows), batch):
            session.run(f"UNWIND $rows AS row MATCH (a:Entity {{id: row.s}}) MATCH (b:Entity {{id: row.t}}) "
                        f"MERGE (a)-[r:{rel}]->(b) SET r += row.props", rows=rows[i:i + batch]).consume()
    session.run("MERGE (m:GraphMeta {name: 'attack'}) SET m.signature = $sig, m.loaded_at = datetime()",
                sig=graph.signature()).consume()
    nodes = session.run("MATCH (e:Entity) RETURN count(e) AS total").single()["total"]
    rels = session.run("MATCH (:Entity)-[r]->(:Entity) RETURN count(r) AS total").single()["total"]
    return {"nodes": nodes, "relationships": rels}


class Neo4jStore:
    """The same graph in Neo4j (load it with scripts/load_neo4j.py). Retrieval runs the Cypher below."""
    name = "neo4j"

    LOCAL = """
    MATCH (tech:Technique) WHERE tech.parent IN $seeds
    MATCH (tech)-[r]-()
    RETURN startNode(r).id AS s, type(r) AS rel, endNode(r).id AS t, properties(r) AS props
    """
    ACTORS = """
    MATCH (actor:Entity)-[r:USES|ATTRIBUTED_TO]->(x:Entity) WHERE actor.id IN $actors
      AND (type(r) = 'ATTRIBUTED_TO' OR x:Technique)
    RETURN actor.id AS s, type(r) AS rel, x.id AS t
    """
    AROUND = """
    MATCH (src:Entity)-[r:ABOUT|USES_DATA]->(x:Entity) WHERE src.id IN $ids
    RETURN src.id AS s, type(r) AS rel, x.id AS t
    """
    NODES = "MATCH (e:Entity) WHERE e.id IN $ids RETURN e {.*} AS node"

    def __init__(self, driver, database: str | None = None):
        self.driver = driver
        self.database = database

    @classmethod
    def connect(cls, uri: str, user: str, password: str, database: str | None = None,
                graph: AttackGraph | None = None, retries: int = 10) -> "Neo4jStore":
        """Connect; with `graph`, (re)load it when Neo4j is empty or holds an older graph."""
        import time as _time
        from neo4j import GraphDatabase

        driver = GraphDatabase.driver(uri, auth=(user, password))
        for attempt in range(retries):          # in docker compose Neo4j may still be starting
            try:
                driver.verify_connectivity()
                break
            except Exception:  # noqa: BLE001
                if attempt == retries - 1:
                    raise
                _time.sleep(3)
        store = cls(driver, database)
        rows = store._run("OPTIONAL MATCH (m:GraphMeta {name: 'attack'}) RETURN m.signature AS sig")
        current = rows[0]["sig"] if rows else None
        if graph is not None and current != graph.signature():
            log.info("Loading the ATT&CK graph into Neo4j (%s)", "first load" if current is None else "graph changed")
            with driver.session(database=database) as session:
                counts = load_into_neo4j(session, graph)
            log.info("Neo4j now holds %s", counts)
        elif not store._run("MATCH (x:Technique) RETURN count(x) AS techniques")[0]["techniques"]:
            raise RuntimeError("Neo4j is reachable but has no ATT&CK graph; run scripts/load_neo4j.py")
        return store

    def _run(self, query: str, **params) -> list[dict]:
        with self.driver.session(database=self.database) as session:
            return [dict(r) for r in session.run(query, **params)]

    @staticmethod
    def _props(props: dict) -> dict:
        props = dict(props or {})
        if isinstance(props.get("chunks"), str):
            props["chunks"] = json.loads(props["chunks"])
        return props

    def local_subgraph(self, seeds: list[str]) -> Subgraph:
        edges = [(r["s"], r["rel"], r["t"], self._props(r["props"])) for r in self._run(self.LOCAL, seeds=seeds)]
        actors = sorted({s for s, rel, _, _ in edges if rel == "USES"} - set(seeds))
        if actors:
            edges += [(r["s"], r["rel"], r["t"], {}) for r in self._run(self.ACTORS, actors=actors)]
        around = sorted({s for s, rel, _, _ in edges if rel in ("DESCRIBES", "DETECTS")})
        if around:
            edges += [(r["s"], r["rel"], r["t"], {}) for r in self._run(self.AROUND, ids=around)]
        unique = _dedupe(edges)
        ids = {x for s, _, t, _ in unique for x in (s, t)} | set(seeds)
        ids = sorted(ids | {i.split(".")[0] for i in ids if re.match(r"T\d+\.\d+$", i)})
        nodes = {}
        for row in self._run(self.NODES, ids=ids):
            node = dict(row["node"])
            node.pop("search_text", None)
            nodes[node["id"]] = node
        return Subgraph(nodes, unique, self.name)

    def users(self, technique_id: str) -> set[str]:
        rows = self._run("MATCH (actor:Entity)-[:USES]->(x:Technique) WHERE x.parent = $p AND NOT actor:Technique "
                         "RETURN DISTINCT actor.id AS actor_id", p=parent_of(technique_id))
        return {r["actor_id"] for r in rows}

    def close(self) -> None:
        self.driver.close()
