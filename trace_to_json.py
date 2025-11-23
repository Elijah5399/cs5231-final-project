#!/usr/bin/env python3
"""
trace_to_json.py

  • Parse raw read_trace dump
  • Build the full event graph directly in memory
  • Output the graph in JSON

Usage:
    python3 trace_to_json.py \
        --in trace.txt \
        --procmap /proc/1234/maps \
        --graphout graph.json \
        --printgraph
"""

from __future__ import annotations
import argparse, re, json
from typing import Dict, List, Optional

# ============================================================
#  REGEX DEFINITIONS
# ============================================================

instr_re = re.compile(r'^\s*\[(\d+)\]\s+(0x[a-fA-F0-9]+):\s*(.+?)\s*$')
mem_re = re.compile(r'^\s*Memory\s+(Read|Write):\s*(\d+)\s*bytes\s*@\s*(0x[a-fA-F0-9]+)\s*$')
regs_start_re = re.compile(r'^\s*Registers:\s*$')
reg_line_re = re.compile(r'^\s*([a-zA-Z0-9_]+)\s*:\s*([0-9a-fA-FxX]+)\s*$')

module_patterns = [
    re.compile(r'^\s*Module\s+Load:\s*(0x[a-fA-F0-9]+)\s*-\s*(0x[a-fA-F0-9]+)\s*(.+)$'),
    re.compile(r'^\s*(.+)\s+loaded\s+at\s+(0x[a-fA-F0-9]+)\s*$'),
    re.compile(r'^\s*(0x[a-fA-F0-9]+)\s*-\s*(0x[a-fA-F0-9]+)\s+(.+)$')
]

maps_re = re.compile(
    r'^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*(.*)$'
)

# ============================================================
#  HELPERS
# ============================================================

def to_int_guess(s: Optional[str]) -> Optional[int]:
    if not s:
        return None
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        try: return int(s,16)
        except: return None
    if re.fullmatch(r'[0-9a-fA-F]+', s):  # hex without 0x
        return int(s,16)
    if s.isdigit():
        return int(s)
    return None

def normalize_hex_str(s: str) -> Optional[str]:
    v = to_int_guess(s)
    return hex(v) if v is not None else None

# ============================================================
#  PROC MAP LOADER
# ============================================================

def load_proc_map(path: str) -> List[Dict]:
    modules = []
    with open(path, "r") as f:
        for ln in f:
            ln = ln.strip()
            if not ln: continue
            m = maps_re.match(ln)
            if m:
                base = int(m.group(1),16)
                end  = int(m.group(2),16)
                pathstr = m.group(7).strip() or None
                modules.append({"base":base,"end":end,"path":pathstr})
    modules.sort(key=lambda x: x["base"])
    return modules

def find_module(mods: List[Dict], addr: int) -> Optional[Dict]:
    for m in mods:
        if m["base"] <= addr < m["end"]:
            return m
    return None

# ============================================================
#  PARSER → GRAPH BUILDER
# ============================================================

def parse_to_graph(fp, modules=None):
    graph = {}
    instr_order = []
    pending_regs = None
    last_instr_id = None
    local_modules = modules or []

    def flush_regs():
        nonlocal pending_regs, last_instr_id
        if pending_regs is not None and last_instr_id is not None:
            if last_instr_id not in graph:
                graph[last_instr_id] = {"instr": None, "regs": None, "mem": [], "next": None}
            graph[last_instr_id]["regs"] = pending_regs
            pending_regs = None

    for raw in fp:
        line = raw.rstrip("\n")

        # Instruction
        mi = instr_re.match(line)
        if mi:
            flush_regs()
            iid = int(mi.group(1))
            addr = mi.group(2)
            bytes_raw = ' '.join(mi.group(3).split())
            last_instr_id = iid
            addr_int = to_int_guess(addr)
            modpath = None
            pc_rel = None
            if modules:
                m = find_module(local_modules, addr_int)
                if m:
                    modpath = m.get("path")
                    pc_rel = hex(addr_int - m["base"])

            if iid not in graph:
                graph[iid] = {"instr": None, "regs": None, "mem": [], "next": None}
            graph[iid]["instr"] = {
                "addr": addr,
                "bytes": bytes_raw,
                "module": modpath,
                "pc_rel": pc_rel
            }
            instr_order.append(iid)
            continue

        # Registers block
        if regs_start_re.match(line):
            flush_regs()
            pending_regs = {}
            continue

        if pending_regs is not None:
            rm = reg_line_re.match(line)
            if rm:
                regname, val = rm.group(1), rm.group(2)
                pending_regs[regname] = normalize_hex_str(val)
                continue
            else:
                flush_regs()

        # Memory
        mm = mem_re.match(line)
        if mm:
            flush_regs()
            op = mm.group(1).lower()
            size = int(mm.group(2))
            addr = mm.group(3)
            if last_instr_id not in graph:
                graph[last_instr_id] = {"instr": None, "regs": None, "mem": [], "next": None}
            graph[last_instr_id]["mem"].append({
                "op": op,
                "size": size,
                "addr": addr
            })
            continue

    flush_regs()

    # Build "next" edges
    for i in range(len(instr_order)-1):
        graph[instr_order[i]]["next"] = instr_order[i+1]

    return graph

# ============================================================
#  MAIN
# ============================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="infile", required=True)
    ap.add_argument("--procmap", help="/proc/<pid>/maps file")
    ap.add_argument("--printgraph", action="store_true")
    ap.add_argument("--graphout", required=False)
    args = ap.parse_args()

    modules = load_proc_map(args.procmap) if args.procmap else None

    with open(args.infile, "r", encoding="utf-8", errors="replace") as fp:
        graph = parse_to_graph(fp, modules)

    if args.printgraph:
        import pprint
        pprint.pprint(graph)

    if args.graphout:
        with open(args.graphout, "w") as g:
            json.dump(graph, g, indent=2)
        print(f"[+] Graph saved to {args.graphout}")

if __name__ == "__main__":
    main()
