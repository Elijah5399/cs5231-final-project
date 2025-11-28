from __future__ import annotations
import argparse, re, json
from typing import Dict, List, Optional
import json

maps_re = re.compile(
    r'^\s*([0-9a-fA-F]+)-([0-9a-fA-F]+)\s+(\S+)\s+([0-9a-fA-F]+)\s+(\S+)\s+(\d+)\s*(.*)$'
)

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

def get_stack_region(mappings: List[Dict]) -> tuple[int, int]:
    for entry in mappings:
        if entry['path'] and entry['path'] == '[stack]':
            return (entry['base'], entry['end'])

def rbp_in_stack_heuristic(threshold: tuple[int,int], instrs: Dict):
    main_addr = 0
    has_main_started = False
    for idx, data in instrs.items():
        # detect the mov rdi, XXX instruction within _start
        if main_addr == 0 and data['instr']['module'] and 'mov rdi' in data['instr']['bytes'] and 'vuln' in data['instr']['module']:
            pos = data['instr']['bytes'].find("mov rdi") + 9
            main_addr = int(data['instr']['bytes'][pos:], 16)
            print(f"main: {hex(main_addr)}")
        if main_addr == 0:
            continue
        if int(data['instr']['addr'], 16) == main_addr:
            has_main_started = True 
        if not has_main_started:
            continue 
        # ensure we are not in the binary's instruction
        if not data['instr']['module'] or 'vuln' not in data['instr']['module']:
            continue
        if not data['regs']:
            # syscall instructions have regs set to null
            continue 
        # we can finally check if rbp is within bounds
        rbp = int(data['regs']['rbp'], 16)
        if rbp < threshold[0] or rbp > threshold[1]: 
            print(f"rbp: {hex(rbp)}, idx: {idx}")
            exit()
        # print(f"idx: {idx}")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--graph", help="graph.json file", required=True)
    ap.add_argument("--procmap", help="/proc/<pid>/maps file", required=True)
    args = ap.parse_args()

    modules = load_proc_map(args.procmap) if args.procmap else None
    instrs = open(args.graph, "r", encoding="utf-8", errors="replace").read()
    instrs = json.loads(instrs)
    # print(modules)
    stack_region = get_stack_region(modules)
    threshold = (stack_region[0] - 0x300000000, stack_region[1])
    print(f"threshold: ({hex(threshold[0])}, {hex(threshold[1])})")
    rbp_in_stack_heuristic(threshold, instrs)

    # print(instrs)

if __name__ == "__main__":
    main()
