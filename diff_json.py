#!/usr/bin/env python3
"""
diff_json.py

  • Compare two trace JSON files
  • Identify the first point of divergence
  • Print a side-by-side comparison of instructions around the divergence point in JSON format
Usage:
    python3 diff_json.py \
        --base base_trace.json \
        --exploit exploit_trace.json \
        --window 5
"""

import json
import pprint
import argparse

def load_trace(path):
    with open(path) as f:
        return json.load(f)

def sort_keys(trace):
    return sorted(trace.keys(), key=lambda x: int(x))

def find_first_divergence(base, exploit):
    keys_base = sort_keys(base)
    keys_exploit = sort_keys(exploit)
    max_len = min(len(keys_base), len(keys_exploit))

    for i in range(max_len):
        step = keys_base[i]  
        step2 = keys_exploit[i]

        addr_base = base[step]["instr"]["addr"]
        addr_exploit = exploit[step2]["instr"]["addr"]

        if addr_base != addr_exploit:
            return step, step2   # return actual JSON keys

    return None

def print_window_side_by_side_json(base, exploit, step_base, step_exploit, window):
    keys_base = sort_keys(base)
    keys_exploit = sort_keys(exploit)

    idx_base = keys_base.index(step_base)
    idx_exploit = keys_exploit.index(step_exploit)

    start = max(0, idx_base - window)
    end   = idx_base + window + 1

    print("\n================ SIDE-BY-SIDE FULL JSON =================\n")

    for i in range(start, end):
        base_step = keys_base[i] if i < len(keys_base) else None
        exploit_step = keys_exploit[i] if i < len(keys_exploit) else None

        # Only print ONE step number per side
        print(f"--- Instruction {base_step if base_step else '<none>'} ---")

        print(f"\n===== BASE ENTRY {base_step} =====")
        pprint.pprint(base[base_step], width=120)

        print(f"\n===== EXPLOIT ENTRY {exploit_step} =====")
        pprint.pprint(exploit[exploit_step], width=120)


        print("-" * 120)


def main():
    parser = argparse.ArgumentParser(description="Find divergence between two instruction traces.")
    parser.add_argument("--base", required=True, help="Path to baseline trace JSON file")
    parser.add_argument("--exploit", required=True, help="Path to exploit trace JSON file")
    parser.add_argument("--window", type=int, default=5, help="Number of instructions before/after divergence to print")

    args = parser.parse_args()

    base = load_trace(args.base)
    exploit = load_trace(args.exploit)

    divergence = find_first_divergence(base, exploit)

    if not divergence:
        print("No divergence found between traces.")
        return

    step_base, step_exploit = divergence

    print("=========================================")
    print(f"First divergence:")
    print(f"BASE instruction {step_base}     addr = {base[step_base]['instr']['addr']}")
    print(f"EXPLOIT instruction {step_exploit} addr = {exploit[step_exploit]['instr']['addr']}")
    print("=========================================\n")

    print_window_side_by_side_json(base, exploit, step_base, step_exploit, args.window)

if __name__ == "__main__":
    main()
