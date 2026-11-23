"""GraphRAG retrieval over the ATT&CK knowledge graph (app/attack_graph.py).

Follows the three stages of Peng et al. (2024), "Graph Retrieval-Augmented Generation: A Survey":
  1. graph-based indexing   the ATT&CK knowledge graph with CTI-HAL reports and technique communities
  2. graph-guided retrieval the local subgraph around the predicted technique (plus the behaviour check's
                            alternative, when it disagrees), ranked by Personalized PageRank from those seeds
  3. graph-enhanced generation  the retrieved paths become numbered "graph" evidence (who uses the technique,
                            what those actors do next, how it is mitigated and detected, its community), next
                            to the text evidence found along the same edges (procedures, CTI spans, CVEs)
The incident's own history (earlier incidents from the same source) is joined to the graph, so the
explanation can say whether the sequence of techniques matches documented tradecraft.
"""
from __future__ import annotations

import math
import re
import time
from collections import Counter

from app.attack_graph import ACTOR_TYPES, AttackGraph, Subgraph, parent_of
from app.knowledge import CVE_TECHNIQUES, KnowledgeBase, Retrieval

# edge weights for Personalized PageRank (tactics and communities are hubs: keep them light)
WEIGHTS = {"USES": 1.0, "DESCRIBES": 0.8, "MITIGATES": 0.6, "DETECTS": 0.4, "USES_DATA": 0.3, "ABOUT": 0.6,
           "ATTRIBUTED_TO": 0.6, "SUBTECHNIQUE_OF": 1.0, "IN_TACTIC": 0.1, "IN_COMMUNITY": 0.1}
METHOD = "Personalized PageRank (alpha 0.85) from the predicted technique over the ATT&CK knowledge graph"
MIN_LIFT = 1.2          # "next technique" must be clearly more common among this technique's users than overall
MIN_SHARE = 0.15        # ... and used by a fair share of them


def _tokens(text: str) -> set[str]:
    return {t for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) > 2}


def _overlap(q: set[str], text: str) -> float:
    d = _tokens(text)
    return len(q & d) / math.sqrt(len(q) * len(d)) if q and d else 0.0


def _names(sub: Subgraph, ids: list[str]) -> str:
    return ", ".join(sub.nodes[i]["name"] for i in ids if i in sub.nodes)


class GraphRetriever:
    def __init__(self, graph: AttackGraph, store, kb: KnowledgeBase, reranker=None):
        self.graph = graph            # in-memory copy (for the knowledge-base stats and the communities)
        self.store = store            # NetworkXStore or Neo4jStore: where retrieval queries run
        self.kb = kb
        self.reranker = reranker      # optional cross-encoder for the text evidence (app.rerank)

    # ------------------------------------------------------------------ retrieval
    def retrieve(self, technique_id: str | None, tactic: str | None, query: str, top_k: int = 5,
                 event: dict | None = None, alternatives: list[str] | None = None,
                 history: list[dict] | None = None) -> Retrieval:
        import networkx as nx

        started = time.perf_counter()
        parent = parent_of(technique_id)
        if not parent or parent not in self.graph.nodes:
            fallback = self.kb.retrieve(technique_id, tactic, query, top_k, event=event)
            fallback.trace["retriever"] = "vector" if self.kb.vector is not None else "token"   # not in the graph
            return fallback
        alts = [a for a in dict.fromkeys(parent_of(a) for a in (alternatives or [])) if a and a != parent
                and a in self.graph.nodes][:2]
        history = history or []
        past = [h["technique_id"] for h in history if parent_of(h["technique_id"]) in self.graph.nodes]
        seeds = list(dict.fromkeys([parent, *alts, *[parent_of(p) for p in past]]))
        sub = self.store.local_subgraph(seeds)

        # 2. Personalized PageRank over the local subgraph
        g = nx.Graph()
        for s, rel, t, _ in sub.edges:
            w = WEIGHTS.get(rel, 0.3)
            if g.has_edge(s, t):
                w = max(w, g[s][t]["weight"])
            g.add_edge(s, t, weight=w)
        personal = {parent: 1.0, **{a: 0.3 / (i + 1) for i, a in enumerate(alts)},
                    **{parent_of(p): 0.2 for p in past if parent_of(p) != parent}}
        personal = {k: v for k, v in personal.items() if k in g}
        rank = nx.pagerank(g, alpha=0.85, personalization=personal, weight="weight") if personal else {}

        def tech(i):
            return sub.nodes.get(i, {}).get("type") == "Technique"

        def users_of(p):          # actors that use the parent technique p or one of its sub-techniques
            return {s for s, rel, t, _ in sub.edges if rel == "USES" and tech(t)
                    and sub.nodes[t].get("parent") == p and sub.nodes.get(s, {}).get("type") in ACTOR_TYPES}

        users = users_of(parent)
        uses: dict[str, set[str]] = {}
        for s, rel, t, _ in sub.edges:
            if rel == "USES" and s in users and tech(t):
                uses.setdefault(s, set()).add(sub.nodes[t]["parent"])
        by_rank = sorted(users, key=lambda a: -rank.get(a, 0))
        groups = [a for a in by_rank if sub.nodes[a]["type"] == "Group"][:4]
        software = [a for a in by_rank if sub.nodes[a]["type"] == "Software"][:3]
        campaigns = [a for a in by_rank if sub.nodes[a]["type"] == "Campaign"][:2]
        node = sub.nodes[parent]

        # what the users of this technique also use, later in the kill chain (lift over the base rate)
        counts = Counter(t for a in users for t in uses.get(a, ()) if t != parent)
        nxt = []
        for t, n in counts.items():
            info = self._technique(sub, t)
            if not info or n < 2:
                continue
            share = n / len(users)
            lift = share / max(info.get("prevalence") or 0.0, 1e-6)
            if lift >= MIN_LIFT:
                nxt.append({"technique_id": t, "name": info["name"], "tactic": (info.get("tactics") or ["?"])[0],
                            "stage": info.get("stage", 99), "actors": n, "share": share, "lift": lift})
        nxt = [x for x in nxt if x["share"] >= MIN_SHARE]
        later = [x for x in nxt if x["stage"] > node.get("stage", 99)]
        pool = later or nxt
        pool.sort(key=lambda x: -(x["share"] * math.log(1 + x["lift"])))
        next_steps = pool[:3]

        mitigations = sorted(sub.into(parent, "MITIGATES"), key=lambda m: -rank.get(m[0], 0))[:3]
        detectors = [d for d, _ in sub.into(parent, "DETECTS")]
        components = Counter(c for d in detectors for c, _ in sub.out(d, "USES_DATA"))
        data = sorted(components, key=lambda c: (not sub.nodes[c]["name"].lower().startswith("network"),
                                                  -components[c]))[:3]
        community = next((c for c, _ in sub.out(parent, "IN_COMMUNITY")), None)

        # ---- evidence: MITRE definition, graph facts, then text found along the selected edges
        evidence: list[dict] = []
        roles: dict[str, list[str]] = {}

        def add(item: dict, nodes: list[str]) -> str:
            item["evidence_id"] = f"E{len(evidence) + 1}"
            item.setdefault("score", 1.0)
            item.setdefault("url", None)
            evidence.append(item)
            for n in nodes:
                roles.setdefault(n, []).append(item["evidence_id"])
            return item["evidence_id"]

        add({"source": "mitre", "level": "technique", "ref": parent, "title": node["name"],
             "text": node.get("description", ""), "url": node.get("url")}, [parent])
        if users:
            kinds = Counter(sub.nodes[a]["type"] for a in users)
            parts = [f"groups {_names(sub, groups)}" if groups else "", f"software {_names(sub, software)}" if software else "",
                     f"campaigns {_names(sub, campaigns)}" if campaigns else ""]
            add({"source": "graph", "level": "path", "ref": parent, "title": f"Who uses {parent} {node['name']}",
                 "text": (f"ATT&CK documents {len(users)} actors using {parent} {node['name']} or a sub-technique "
                          f"({kinds['Group']} groups, {kinds['Software']} software, {kinds['Campaign']} campaigns). "
                          f"Most related to this incident: {'; '.join(p for p in parts if p)}. This is documented "
                          "tradecraft, not attribution of this incident.")}, [parent, *groups, *software, *campaigns])
        if next_steps:
            add({"source": "graph", "level": "path", "ref": parent, "title": f"What actors that use {parent} do next",
                 "text": f"Of the {len(users)} actors that use {parent} {node['name']}, "
                         + "; ".join(f"{x['actors']} ({x['share']:.0%}) also use {x['technique_id']} {x['name']} "
                                     f"({x['tactic']})" for x in next_steps)
                         + "." + ("" if later else " None of these is in a later tactic; they are used alongside it.")},
                [x["technique_id"] for x in next_steps])
        if mitigations or data:
            text = []
            if mitigations:
                text.append("Mitigated by " + "; ".join(f"{m} {sub.nodes[m]['name']}" for m, _ in mitigations) + ".")
            if data:
                text.append("Detected with the data components " + ", ".join(sub.nodes[c]["name"] for c in data) + ".")
            add({"source": "graph", "level": "path", "ref": parent, "title": f"How to mitigate and detect {parent}",
                 "text": " ".join(text)}, [m for m, _ in mitigations] + data)
        if community and community in sub.nodes:
            add({"source": "graph", "level": "community", "ref": community, "title": f"{parent} belongs to {sub.nodes[community]['name']}",
                 "text": sub.nodes[community].get("description", "")}, [community])
        for a in alts:
            info = self._technique(sub, a) or {"name": a}
            shared = len(users & users_of(a))
            add({"source": "graph", "level": "path", "ref": a, "title": f"Alternative: {a} {info['name']}",
                 "text": (f"The behaviour check suggests {a} {info['name']} ({(info.get('tactics') or ['?'])[0]}). "
                          f"{shared} of the {len(users)} actors that use {parent} also use {a}. "
                          + (info.get("description") or "")[:300])}, [a])
        if history:
            # the log context: earlier incidents from this source, joined to the graph through their techniques
            seen_t = Counter(parent_of(h["technique_id"]) for h in history)
            other = [h for h in history if parent_of(h["technique_id"]) != parent]
            text = (f"{len(history)} earlier incident(s) from this source in the previous 24 hours, first at "
                    f"{history[0]['first_seen']}: " + ", ".join(
                        f"{n} x {t} {(self._technique(sub, t) or {'name': ''})['name']}".strip() for t, n in seen_t.most_common(3)) + ".")
            linked = []
            if other:
                p = parent_of(other[-1]["technique_id"])
                p_users = users_of(p) if p in sub.nodes else set()
                both = len(p_users & users)
                if p_users and both:
                    text += (f" The source moved from {p} to {parent}; in ATT&CK, {both} of the {len(p_users)} actors "
                             f"that use {p} also use {parent}, so this sequence matches documented tradecraft.")
                    linked = [p]
            else:
                text += f" The source keeps repeating {parent}, which points to an ongoing or automated activity."
            add({"source": "graph", "level": "history", "ref": parent, "title": "Earlier activity from this source",
                 "text": text}, linked)

        q = _tokens(query)
        texts: list[tuple[float, dict, list[str]]] = []
        for a in [*groups, *software, *campaigns][:4]:          # procedure examples on the actor -> technique edges
            for s, rel, t, props in sub.edges:
                if s == a and rel == "USES" and tech(t) and sub.nodes[t]["parent"] == parent and props.get("text"):
                    texts.append((rank.get(a, 0) * 10 + _overlap(q, props["text"]),
                                  {"source": "procedure", "level": "procedure", "ref": a, "title": sub.nodes[a]["name"],
                                   "text": props["text"], "url": sub.nodes[a].get("url")}, [a]))
                    break
        top_actors = set(groups + software + campaigns)
        for r, props in sub.into(parent, "DESCRIBES"):           # CTI-HAL spans on the report -> technique edges
            about = {g for g, _ in sub.out(r, "ABOUT")}
            for chunk in props.get("chunks", [])[:4]:
                texts.append((0.5 * bool(about & top_actors) + rank.get(r, 0) * 10 + _overlap(q, chunk["text"]),
                              {"source": "cti", "level": "technique", "ref": sub.nodes[r]["name"][:60],
                               "title": " ".join(x for x in [sub.nodes[r].get("apt_group"), sub.nodes[r]["name"]] if x),
                               "text": chunk["text"], "url": sub.nodes[r].get("url")}, [r, *about]))
        texts.sort(key=lambda x: -x[0])
        rerank_trace = None
        if self.reranker is not None and len(texts) > 1:
            texts, rerank_trace = self.reranker.rerank(query, texts, lambda x: x[1]["text"])
        seen, picked, per_report, per_source = set(), 0, Counter(), Counter()
        for score, item, nodes in texts:
            if (picked >= top_k or item["text"] in seen or per_report[item["title"]] >= 2
                    or (item["source"] == "procedure" and per_source["procedure"] >= 3)):
                continue
            per_source[item["source"]] += 1
            seen.add(item["text"])
            per_report[item["title"]] += 1
            item["score"] = round(score, 3)
            add(item, nodes)
            picked += 1
        cve = []
        if parent in CVE_TECHNIQUES:
            cve = [e for e in self.kb.retrieve(technique_id, tactic, query, top_k, event=event).evidence if e["source"] == "cve"]
            for e in cve[:2]:
                add({k: v for k, v in e.items() if k != "evidence_id"}, [parent])

        # ---- the subgraph the console draws (seed, its tactic, actors, next techniques, defences, community)
        show = [parent, *[t for t, _ in sub.out(parent, "IN_TACTIC")][:1], *groups, *software, *campaigns,
                *[x["technique_id"] for x in next_steps], *[m for m, _ in mitigations], *data,
                *([community] if community else []), *alts,
                *[parent_of(h["technique_id"]) for h in history[-3:] if parent_of(h["technique_id"]) != parent]]
        show = [n for n in dict.fromkeys(show) if n in sub.nodes]
        role = {parent: "seed", **{a: "user" for a in groups + software + campaigns},
                **{x["technique_id"]: "next" for x in next_steps}, **{m: "mitigation" for m, _ in mitigations},
                **{c: "data" for c in data}, **({community: "community"} if community else {}),
                **{a: "alternative" for a in alts}}
        for h in history:
            role.setdefault(parent_of(h["technique_id"]), "history")
        for t, _ in sub.out(parent, "IN_TACTIC"):
            role.setdefault(t, "tactic")
        shown = set(show)
        edges = []
        for s, rel, t, _ in sub.edges:
            a, b = s, t
            if tech(s) and s not in shown and sub.nodes[s].get("parent") in shown:
                a = sub.nodes[s]["parent"]              # draw sub-technique edges on the parent
            if tech(t) and t not in shown and sub.nodes[t].get("parent") in shown:
                b = sub.nodes[t]["parent"]
            if a in shown and b in shown and a != b and rel not in ("SUBTECHNIQUE_OF",):
                edges.append({"source": a, "target": b, "relation": rel})
        edges = list({(e["source"], e["target"], e["relation"]): e for e in edges}.values())
        for d in detectors:                             # strategy nodes are not drawn: link the data to the technique
            for c, _ in sub.out(d, "USES_DATA"):
                if c in shown:
                    edges.append({"source": parent, "target": c, "relation": "DETECTED_WITH"})
        edges = list({(e["source"], e["target"], e["relation"]): e for e in edges}.values())
        nodes = [{"id": n, "type": sub.nodes[n]["type"], "name": sub.nodes[n]["name"], "role": role.get(n, "context"),
                  "score": round(rank.get(n, 0.0), 5), "evidence_ids": roles.get(n, []),
                  "url": sub.nodes[n].get("url")} for n in show]

        latency = int((time.perf_counter() - started) * 1000)
        sources = [{"source": "mitre", "returned": 1},
                   {"source": "graph", "returned": sum(e["source"] == "graph" for e in evidence)},
                   {"source": "procedure", "searched": sum(1 for x in texts if x[1]["source"] == "procedure"),
                    "returned": sum(e["source"] == "procedure" for e in evidence)},
                   {"source": "cti", "searched": sum(1 for x in texts if x[1]["source"] == "cti"),
                    "returned": sum(e["source"] == "cti" for e in evidence)},
                   {"source": "cve", "returned": len(cve[:2]), **({} if parent in CVE_TECHNIQUES else {"skipped": True})}]
        trace = {"query": query, "sources": sources, "top_k": top_k, "min_score": None, "fallback_to_tactic": False,
                 "latency_ms": latency, "retriever": "graph", "rerank": rerank_trace,
                 "graph": {"store": sub.store, "method": METHOD, "seeds": seeds,
                           "subgraph": {"nodes": len(sub.nodes), "edges": len(sub.edges)},
                           "actors": len(users), "community": sub.nodes[community]["name"] if community else None,
                           "nodes": nodes, "edges": edges}}
        return Retrieval(evidence, trace, "applicable" if parent in CVE_TECHNIQUES else "not_applicable", False)

    @staticmethod
    def _technique(sub: Subgraph, tid: str) -> dict | None:
        info = sub.nodes.get(tid)
        return info if info and info.get("type") == "Technique" else None
