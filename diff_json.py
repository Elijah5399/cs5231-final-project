#!/usr/bin/env python3
"""
diff_json.py

• Find divergence between base and exploit JSON traces
• Print window around divergence
• Detect Use-After-Free (UAF) via backtracking using procmap for heap ranges

Usage:
    python3 diff_json.py \
        --base base.json \
        --exploit exploit.json \
        --procmap procmap.txt \
        --window 5
"""

import json
import pprint
import argparse
import os

# ---------------------------
# Helpers
# ---------------------------

def load_trace(path):
    with open(path) as f:
        return json.load(f)

def sort_keys(trace):
    return sorted(trace.keys(), key=lambda x: int(x))


# ---------------------------
# Find first divergence
# ---------------------------

def find_first_divergence(base, exploit):
    keys_base = sort_keys(base)
    keys_exploit = sort_keys(exploit)
    max_len = min(len(keys_base), len(keys_exploit))

    for i in range(max_len):
        sb = keys_base[i]
        se = keys_exploit[i]

        if base[sb]["instr"]["addr"] != exploit[se]["instr"]["addr"]:
            return sb, se

    return None


# ---------------------------
# print window
# ---------------------------

def print_window_side_by_side_json(base, exploit, step_base, step_exploit, window):
    keys_base = sort_keys(base)
    keys_exploit = sort_keys(exploit)

    idx_base = keys_base.index(step_base)
    start = max(0, idx_base - window)
    end   = idx_base + window + 1

    print("\n================ SIDE-BY-SIDE FULL JSON =================\n")

    for i in range(start, end):
        base_step    = keys_base[i] if i < len(keys_base) else None
        exploit_step = keys_exploit[i] if i < len(keys_exploit) else None

        print(f"--- Instruction {base_step} ---\n")

        print(f"===== BASE ENTRY {base_step} =====")
        pprint.pprint(base[base_step], width=120)

        print(f"\n===== EXPLOIT ENTRY {exploit_step} =====")
        pprint.pprint(exploit[exploit_step], width=120)

        print("-" * 120)


# ---------------------------
# Procmap parsing
# ---------------------------

def parse_heap_ranges_from_procmap(path):
    """
    Parse procmap-like file to extract all heap candidate ranges.
    Includes:
      • [heap] labeled segments
      • Anonymous RW segments after binary code/data (no-PIE fallback)
    """
    if not os.path.exists(path):
        raise SystemExit(f"[ERROR] procmap file not found: {path}")

    heap_ranges = []

    candidate_rw = []

    with open(path, "r") as f:
        for line in f:
            parts = line.split()
            if len(parts) < 2:
                continue

            addr_range = parts[0].split("-")
            if len(addr_range) != 2:
                continue
            start, end = int(addr_range[0], 16), int(addr_range[1], 16)

            perms = parts[1]

            # anonymous RW segment
            if perms.startswith("rw") and (len(parts) < 6 or parts[5] == "0"):
                candidate_rw.append((start, end))

    # Include large RW anonymous segments as potential heap
    candidate_rw.sort(key=lambda x: x[1] - x[0], reverse=True)
    heap_ranges.extend(candidate_rw)

    if not heap_ranges:
        raise SystemExit("[ERROR] Could not find any heap candidates in procmap")

    return heap_ranges


# ---------------------------
# UAF Detection Heuristics
# ---------------------------

def is_free_call(entry, trace=None, step_idx=None, keys=None, heap_ranges=None, freed_ptrs=None):
    """
    Determine if the instruction looks like a function call (likely free)
    and validate via heap write (forward scanning).

    Parameters:
        entry       : current instruction entry (dict)
        trace       : full exploit trace (dict), optional
        step_idx    : current step index in keys, optional
        keys        : sorted list of trace keys, optional
        heap_ranges : list of heap ranges, optional

    Returns:
        freed pointer (int) if validated, else None
    """
    instr_bytes = entry["instr"]["bytes"].split()
    regs = entry.get("regs")
    if not regs or "rdi" not in regs:
        return None

    try:
        ptr = int(regs["rdi"], 16)
    except:
        return None

    b = [x.lower() for x in instr_bytes]

    # CALL rel32: E8 xx xx xx xx 
    if len(b) == 5 and b[0] == "e8":
        pass
    # CALL qword ptr: FF 15 xx xx xx xx
    elif len(b) == 6 and b[0] == "ff" and b[1] == "15":
        pass
    # CALL r/m64: FF D0 .. FF D3
    elif len(b) == 2 and b[0] == "ff" and b[1] in ("d0", "d1", "d2", "d3"):
        pass
    else:
        return None
    
    # quick check for double free, since the 2nd validation does not apply as the process will abort
    if ptr in freed_ptrs:
        return ptr

    #  validate via heap write
    if trace is not None and keys is not None and step_idx is not None and heap_ranges is not None:
        def is_in_heap(addr):
            for start, end in heap_ranges:
                if start <= addr <= end:
                    return True
            return False

        if not is_in_heap(ptr):
            return None

        # Forward scan to confirm heap write near freed pointer
        idx = keys.index(step_idx)
        for j in range(idx + 1, min(len(keys), idx + 1000)):
            memops = trace[keys[j]].get("mem", [])
            module = trace[keys[j]]["instr"]["module"]

            for m in memops:
                if m["op"] == "write" and module is None:
                    addr = int(m["addr"], 16)
                    if ptr - 0x20 <= addr <= ptr + 0x20:
                        return ptr

        # If no heap write found, not a confirmed free
        return None

    # If no trace provided, just return ptr (heuristic only)
    return ptr


def forward_trace_uaf(exploit, divergence_step, heap_ranges):
    """
    Forward trace from divergence position to detect:
        • all free(ptr) events
        • all UAF accesses
    Returns:
        ("UAF", results) where results is a list of dicts:
            {
                "freed_ptr": ptr,
                "access_step": step,
                "access_addr": addr,
                "instr_addr": entry["instr"]["addr"]
            }
        or ("NONE", [])
    """

    keys = sort_keys(exploit)
    idx = keys.index(divergence_step)

    freed_ptrs = set()
    uaf_events = []
    double_free_events = []

    def is_in_heap(addr):
        for start, end in heap_ranges:
            if start <= addr <= end:
                return True
        return False

    # Forward trace from divergence
    for i in range(idx, len(keys)):
        step = keys[i]
        entry = exploit[step]

        # --------------------
        # Detect free(ptr)
        # --------------------
        ptr = is_free_call(entry, exploit, step, keys, heap_ranges, freed_ptrs)
        if ptr in freed_ptrs:
            double_free_events.append({
                "freed_ptr": ptr,
                "step": step,
                "instr_addr": entry["instr"]["addr"]
            })
            continue
        if ptr:
            freed_ptrs.add(ptr)
            continue


        # --------------------
        # Detect UAF access
        # --------------------
        memops = entry.get("mem", [])
        module = entry["instr"]["module"]

        for m in memops:
            addr = int(m["addr"], 16)

            # skip non-heap or non-user accesses
            if not is_in_heap(addr) or module is None:
                continue

            # check against all freed pointers
            for fp in freed_ptrs:
                if fp <= addr <= fp:   # small range to catch struct accesses
                    uaf_events.append({
                        "freed_ptr": fp,
                        "access_step": step,
                        "access_addr": hex(addr),
                        "instr_addr": entry["instr"]["addr"]
                    })

    vulns = {}

    if uaf_events:
        vulns["UAF"] = uaf_events

    if double_free_events:
        vulns["DOUBLE_FREE"] = double_free_events

    if not vulns:
        return "NONE", []

    return "MULTIPLE", vulns



# ---------------------------
# main
# ---------------------------

def main():
    parser = argparse.ArgumentParser(description="Find divergence and detect memory error.")
    parser.add_argument("--base", required=True)
    parser.add_argument("--exploit", required=True)
    parser.add_argument("--procmap", required=True, help="Procmap file for heap ranges")
    parser.add_argument("--window", type=int, default=5)
    args = parser.parse_args()

    base = load_trace(args.base)
    exploit = load_trace(args.exploit)
    heap_ranges = parse_heap_ranges_from_procmap(args.procmap)

    divergence = find_first_divergence(base, exploit)
    if not divergence:
        print("No divergence found!")
        return

    step_base, step_exploit = divergence

    print("=========================================")
    print("First divergence:")
    print(f"BASE    step {step_base}    addr={base[step_base]['instr']['addr']}")
    print(f"EXPLOIT step {step_exploit} addr={exploit[step_exploit]['instr']['addr']}")
    print("=========================================\n")

    print_window_side_by_side_json(base, exploit, step_base, step_exploit, args.window)

    # ---------------------------
    # UAF Detection
    # ---------------------------
    print("\n========== ANALYZING ROOT CAUSE ==========\n")

    vulntype, events = forward_trace_uaf(exploit, step_exploit, heap_ranges)


    if vulntype == "NONE":
        print("No vulnerabilities detected (based on current heuristics)")
    elif vulntype == "MULTIPLE":
        print("Vulnerability Classification:\n")
        
        if "UAF" in events:
            print("=== USE-AFTER-FREE (UAF) Events ===")
            for ev in events["UAF"]:
                print(f"- Freed ptr:       {hex(ev['freed_ptr'])}")
                print(f"  UAF access step: {ev['access_step']}")
                print(f"  Instruction:       {ev['instr_addr']}\n")
                
        if "DOUBLE_FREE" in events:
            print("=== DOUBLE FREE Events ===")
            for ev in events["DOUBLE_FREE"]:
                print(f"- Freed ptr: {hex(ev['freed_ptr'])}")
                print(f"  Second freed Step:      {ev['step']}")
                print(f"  Instruction: {ev['instr_addr']}\n")
 


if __name__ == "__main__":
    main()
