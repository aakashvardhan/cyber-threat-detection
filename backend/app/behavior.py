"""Behaviour check: which ATT&CK techniques does the traffic itself point to?

The detector's technique head can only name techniques it saw in training. This module describes an
incident's traffic in words and searches ALL ATT&CK techniques with that description, without the
detector's technique as a filter. The result is shown next to the detector's technique, and the LLM
sees both, so a technique the detector never learned can still surface.

Steps
1. incident_features(): aggregate the incident's edges (Zeek conn features)
2. facts(): the traffic in numbers, worded like the RAG notebook's edge_to_event()
3. interpret(): a short analyst reading of those facts (standard network-security heuristics)
4. TechniqueIndex.rank(): BM25 over technique documents (name, description, detection analytics),
   fused with vector search when the vector store is available

Offline evaluation (leave-one-recording-out, notebooks/RAG): searching with the facts alone finds almost
nothing; the analyst reading is what makes the search work.
"""
from __future__ import annotations

import json
import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

import pandas as pd

try:  # optional: better matching of word forms (scan / scanning)
    from nltk.stem import PorterStemmer
    _stem = PorterStemmer().stem
except Exception:  # noqa: BLE001
    def _stem(word: str) -> str:
        return word

INTERNAL_IP = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|143\.88\.)")
FAILED_STATES = ("S0", "REJ", "RSTO", "RSTR", "RSTOS0", "RSTRH", "SH", "OTH")
PORT_WORDS = {21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http web", 88: "kerberos",
              110: "pop3 email", 123: "ntp", 135: "rpc", 139: "netbios smb", 143: "imap email",
              161: "snmp", 389: "ldap", 443: "https tls web", 445: "smb", 636: "ldaps", 1433: "mssql database",
              3306: "mysql database", 3389: "rdp remote desktop", 5432: "postgres database",
              5900: "vnc remote", 5985: "winrm", 8080: "http web proxy"}
AUTH_SERVICES = {"ssh", "rdp", "ftp", "telnet", "smb", "pop3", "imap", "smtp", "mysql", "mssql", "postgresql",
                 "ldap", "kerberos", "vnc", "winrm", "krb", "krb_tcp", "ntlm"}
AUTH_PORTS = {21, 22, 23, 25, 88, 110, 143, 389, 445, 1433, 3306, 3389, 5432, 5900, 5985}
WEB_PORTS = {80, 443, 8000, 8008, 8080, 8443, 8888, 4848, 7001, 9090}
PORT_GROUPS = [("80/443", {80, 443, 8080, 8443, 8000, 8008, 8888}), ("22", {22}), ("445/3389", {445, 3389}), ("53", {53})]
# Not observable from Zeek conn logs (RAG notebook, section 7)
HOST_ONLY = {"T1204", "T1547", "T1136", "T1059", "T1112", "T1546"}
NETWORK_LOG_PREFIXES = ("nsm:", "netflow", "networkdevice:flow", "aws:vpcflowlogs", "vpcflowlogs",
                        "azure:vpcflow", "gcp:vpcflow", "nsx:flowlogs", "network traffic")
STOP = set("""the and for with that this from are may can use used using such other into their they which have
has been also more than then when where these those will within via its not but all any adversaries adversary
e.g eg i.e ie""".split())


# ------------------------------------------------------------------ features

def _num(rows: pd.DataFrame, column: str) -> pd.Series:
    return pd.to_numeric(rows[column], errors="coerce").fillna(0) if column in rows else pd.Series(0, index=rows.index)


def incident_features(rows: pd.DataFrame) -> dict:
    """Aggregate the replay rows of an incident's edges."""
    conns = _num(rows, "connection_count")
    ports = pd.to_numeric(rows.get("most_common_destination_port", rows.get("dominant_destination_port",
                                                                          pd.Series(dtype=float))), errors="coerce")
    port_conns = Counter()
    for p, c in zip(ports, conns):
        if pd.notna(p):
            port_conns[int(p)] += float(c)
    states = Counter()
    if "most_common_connection_state" in rows:
        for s, c in zip(rows["most_common_connection_state"], conns):
            if isinstance(s, str) and s:
                states[s] += float(c)
    services = Counter(s for s in rows.get("most_common_service", rows.get("dominant_zeek_service", pd.Series(dtype=str)))
                       if isinstance(s, str) and s and s not in ("-", "unknown"))
    windows = pd.to_datetime(rows["window_start"])
    dests = rows["dest_ip_zeek"].astype(str)
    return {
        "connections": int(conns.sum()),
        "target_count": int(dests.nunique()),
        "minutes": int((windows.max() - windows.min()).total_seconds() // 60) + 5,
        "max_unique_ports": int(_num(rows, "unique_destination_ports").max()),
        "distinct_ports": len(port_conns),
        "ports": [p for p, _ in port_conns.most_common(8)],
        "port_conns": dict(port_conns),
        "services": [s for s, _ in services.most_common(4)],
        "states": states,
        "avg_duration": float(_num(rows, "total_duration").sum() / max(conns.sum(), 1)),
        "orig_bytes": float(_num(rows, "total_orig_bytes").sum()),
        "resp_bytes": float(_num(rows, "total_resp_bytes").sum()),
        "proto_counts": {p: float(_num(rows, f"{p}_count").sum()) for p in ("tcp", "udp", "icmp")},
        "src_internal": bool(INTERNAL_IP.match(str(rows["src_ip_zeek"].iat[0]))),
        "dst_internal_share": float(dests.str.match(INTERNAL_IP).mean()),
    }


def _port_label(p: int) -> str:
    for label, group in PORT_GROUPS:
        if p in group:
            return label
    return "other well-known (<1024)" if p < 1024 else "registered (1024-49151)" if p < 49152 else "ephemeral (>=49152)"


def event_fields(f: dict) -> dict:
    """The notebook's edge_to_event() fields, aggregated over the incident: behavior, service, protocol, port group."""
    proto = max(f["proto_counts"], key=f["proto_counts"].get) if any(f["proto_counts"].values()) else "unknown"
    n, hosts = f["connections"], f["target_count"]
    groups = Counter()
    for p, c in f["port_conns"].items():
        groups[_port_label(int(p))] += c
    pg = groups.most_common(1)[0][0] if groups else "unknown"
    total = sum(f["states"].values())
    state_text = ""
    if total:
        fail = sum(f["states"].get(s, 0) for s in FAILED_STATES) / total
        state_text = f"; {fail:.0%} failed or rejected, {f['states'].get('SF', 0) / total:.0%} completed normally"
    service = (f["services"] or [{"80/443": "http", "22": "ssh", "445/3389": "smb", "53": "dns"}.get(pg, "unknown")])[0]
    src = "internal host" if f["src_internal"] else "external host"
    dst = "internal" if f["dst_internal_share"] >= 0.5 else "external"
    ports = max(f["max_unique_ports"], f["distinct_ports"])
    behavior = (f"{src} made {n:,} {proto.upper()} connection{'s' if n != 1 else ''} to "
                f"{'one ' + dst + ' host' if hosts == 1 else f'{hosts} {dst} hosts'} within {f['minutes']} minutes, "
                f"{ports} distinct destination port{'s' if ports != 1 else ''} (mostly {pg}){state_text}; "
                f"about {f['orig_bytes'] / max(n, 1):,.0f} bytes sent per connection")
    return {"behavior": behavior, "service": service, "protocol": proto, "port": pg}


def facts(f: dict) -> str:
    """The traffic in numbers (wording of the RAG notebook's edge_to_event() query)."""
    e = event_fields(f)
    return f"{e['behavior']} over {e['service']}/{e['protocol']} port {e['port']}"


def interpret(f: dict) -> list[str]:
    """Analyst reading of the traffic: standard NSM heuristics, not fitted to the UWF labels."""
    out = []
    total = sum(f["states"].values()) or 1
    failed = sum(f["states"].get(s, 0) for s in FAILED_STATES) / total
    many_ports = f["max_unique_ports"] >= 20 or f["distinct_ports"] >= 20
    many_hosts = f["target_count"] >= 20
    services = set(f["services"])
    ports = set(f["ports"])
    if many_ports:
        out.append("port scan probing many ports to discover open services, scanning reconnaissance")
    if many_hosts:
        out.append("host sweep scanning many IP addresses to discover remote systems on the network")
    if failed >= 0.3 and (many_ports or many_hosts or f["connections"] >= 100):
        out.append("many failed, unanswered or rejected connection attempts typical of scanning")
    if ((services & AUTH_SERVICES) or (ports & AUTH_PORTS)) and f["connections"] >= 20 and not many_ports:
        names = ", ".join(sorted(services & AUTH_SERVICES) or [PORT_WORDS.get(p, str(p)) for p in sorted(ports & AUTH_PORTS)])
        out.append(f"repeated login attempts against {names} authentication; password guessing, credential login with accounts")
    if (({"http", "ssl"} & services) or (ports & WEB_PORTS)) and f["connections"] >= 20 and not many_ports:
        out.append("many requests to a web application or web server; possible exploit of an internet-facing application")
    if "dns" in services and f["connections"] >= 20:
        out.append("many DNS queries; DNS lookups")
    if f["orig_bytes"] > 1_000_000 and f["orig_bytes"] > 5 * max(f["resp_bytes"], 1):
        out.append("large outbound data transfer from the host; data exfiltration")
    return out or ["network connections between hosts"]


def _services(f: dict) -> list[str]:
    return sorted(set(f["services"]) | {PORT_WORDS[p] for p in f["ports"] if p in PORT_WORDS})


# ------------------------------------------------------------------ technique documents

def _clean(text: str) -> str:
    text = re.sub(r"\(Citation:[^)]*\)", "", text or "")
    text = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", text)
    return re.sub(r"\s+", " ", text).strip()


def build_technique_docs(stix_path: Path) -> dict[str, dict]:
    """One document per parent technique: name, description(s), and detection analytics from network sensors."""
    objs = {o["id"]: o for o in json.loads(Path(stix_path).read_text(encoding="utf-8"))["objects"]}
    docs, parent_of = {}, {}
    for sid, o in objs.items():
        if o["type"] != "attack-pattern" or o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        tid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if not tid:
            continue
        parent = tid.split(".")[0]
        parent_of[sid] = parent
        d = docs.setdefault(parent, {"name": None, "parts": [], "net": []})
        if "." not in tid:
            d["name"] = o["name"]
        d["parts"].append(o["name"] + ". " + _clean(o.get("description", "")))
    for rel in objs.values():
        if rel["type"] != "relationship" or rel.get("relationship_type") != "detects":
            continue
        parent, strategy = parent_of.get(rel["target_ref"]), objs.get(rel["source_ref"])
        if not parent or not strategy:
            continue
        for aid in strategy.get("x_mitre_analytic_refs", []):
            an = objs.get(aid) or {}
            sources = [s.get("name", "").lower() for s in an.get("x_mitre_log_source_references", [])]
            if any(s.startswith(NETWORK_LOG_PREFIXES) for s in sources):
                docs[parent]["net"].append(_clean(strategy.get("name", "")) + ". " + _clean(an.get("description", "")))
    return {t: {"name": d["name"], "text": " ".join(d["parts"]), "network_text": " ".join(d["net"])}
            for t, d in docs.items() if d["name"]}


def _tokens(text: str) -> list[str]:
    return [_stem(t) for t in re.findall(r"[a-z0-9]+", (text or "").lower()) if len(t) > 2 and t not in STOP]


class TechniqueIndex:
    """BM25 over technique documents (analytics text counts twice: it describes observable behaviour)."""

    def __init__(self, docs: dict[str, dict], k1: float = 1.5, b: float = 0.75):
        self.docs = docs
        self.ids = list(docs)
        self.tf, lengths, df = [], [], Counter()
        for t in self.ids:
            d = docs[t]
            toks = _tokens(f"{d['name']} {d['name']} {d['text']} {d['network_text']} {d['network_text']}")
            counts = Counter(toks)
            self.tf.append(counts)
            lengths.append(len(toks))
            df.update(counts.keys())
        n = len(self.ids)
        self.avg = sum(lengths) / max(n, 1)
        self.lengths = lengths
        self.idf = {w: math.log((n - c + 0.5) / (c + 0.5) + 1) for w, c in df.items()}
        self.k1, self.b = k1, b

    def rank(self, query: str, k: int = 10) -> list[tuple[str, float]]:
        q = _tokens(query)
        scores = []
        for i, tf in enumerate(self.tf):
            norm = self.k1 * (1 - self.b + self.b * self.lengths[i] / self.avg)
            s = sum(self.idf.get(w, 0) * tf[w] * (self.k1 + 1) / (tf[w] + norm) for w in q if w in tf)
            scores.append(s)
        order = sorted(range(len(self.ids)), key=lambda i: -scores[i])[:k]
        return [(self.ids[i], scores[i]) for i in order if scores[i] > 0]


def _fuse(*rankings: list[str], k: int = 60) -> list[str]:
    score = Counter()
    for ranking in rankings:
        for i, t in enumerate(ranking):
            score[t] += 1 / (k + i + 1)
    return [t for t, _ in score.most_common()]


@dataclass
class BehaviorSearch:
    index: TechniqueIndex | None
    vector: object | None = None   # VectorStore with a "techniques" collection

    @classmethod
    def load(cls, stix_path: Path | None, vector=None) -> "BehaviorSearch":
        if stix_path is None or not Path(stix_path).exists():
            return cls(None, None)
        return cls(TechniqueIndex(build_technique_docs(stix_path)), vector)

    @property
    def enabled(self) -> bool:
        return self.index is not None

    def check(self, f: dict, detector_technique: str | None, top: int = 5) -> dict | None:
        if not self.enabled:
            return None
        reading = interpret(f)
        lexical = [t for t, _ in self.index.rank(". ".join(reading) + ". Services: " + ", ".join(_services(f)), 10)
                   if t not in HOST_ONLY]
        method = "bm25"
        ranked = lexical
        if self.vector is not None and getattr(self.vector, "has_techniques", False):
            semantic = [t for t in self.vector.techniques_for(". ".join(reading), 10) if t not in HOST_ONLY]
            ranked, method = _fuse(semantic, lexical), "bm25+vector"
        top_ids = ranked[:top]
        parent = (detector_technique or "").split(".")[0]
        return {
            "facts": facts(f),
            "reading": reading,
            "method": method,
            "candidates": [{"technique_id": t, "name": self.index.docs[t]["name"], "rank": i + 1}
                           for i, t in enumerate(top_ids)],
            "agrees_with_detector": (parent in top_ids[:3]) if parent else None,
        }
