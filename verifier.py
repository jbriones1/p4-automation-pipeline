# python verifier.py example.json test.p4

#!/usr/bin/env python3

import subprocess
import json
import re
import sys
from pathlib import Path
from typing import Set

def clean_identifier(name: str) -> str:
    """
    Conver a string to valid identifier matching cna2p4.py
    - Replace non-alphanumeric characters with underscores
    - If starts with digit, prepend underscore
    """
    s = re.sub(r'[^a-zA-Z0-9_]', '_', name)
    if not s:
        s = 'x'  # default name if empty
    if s[0].isdigit():
        s = '_' + s
    return s

# Part 1: Compilation
def compile_p4(p4_file: str) -> bool:
    """
    Try to compile a P4 file using p4c
    Returns True if compilation succeeds, False otherwise
    """
    print(f"Compiling {p4_file}")
    
    # create build directory if it don't exist
    build_dir = Path("build")
    build_dir.mkdir(exist_ok=True)
    
    # output JSON
    p4_path = Path(p4_file)
    output_file = build_dir / f"{p4_path.stem}.json"
    
    # p4c command
    cmd = [
        "p4c",
        "--target", "bmv2",
        "--arch", "v1model",
        "--output", str(output_file),
        p4_file
    ]
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            print(f"Compilation successful! Output: {output_file}")
            return True
        else:
            print(f"Compilation failed")
            print("\nError output:")
            print(result.stderr)
            return False
            
    except FileNotFoundError:
        print("p4c not found")
        return False
    except subprocess.TimeoutExpired:
        print("Compilation timed out")
        return False
    
# Part 2: Header verification
def extract_headers_p4(p4_file: str) -> Set[str]:
    """
    Extract header names from P4 file (without _t suffix)
    """
    with open(p4_file, 'r') as f:
        content = f.read()
    
    pattern = r'header\s+(\w+_t)\s*\{'
    headers_with_t = re.findall(pattern, content)
    
    headers = set()
    for h in headers_with_t:
        if h.endswith('_t'):
            headers.add(h[:-2])  # Remove the '_t'
        else:
            headers.add(h)
    
    return headers

def extract_headers_cna(cna_file: str) -> Set[str]:
    """
    Extrace header names from CNA JSON file
    """

    with open(cna_file, 'r') as f:
        cna = json.load(f)
    
    headers = set()
    
    #add network instances
    for net in cna.get("networks", []):
        headers.add(clean_identifier(net["id"]))

    #add session protocols
    for protocol in cna.get("protocols", []):
        if protocol.get("role") == "session":
            headers.add(clean_identifier(protocol["id"]))

    return headers

def verify_headers(cna_file: str, p4_file: str) -> bool:
    """
    Compre headers from CNA and P4 files
    Returns True if all headers match
    """

    print("\n Verifying headers...")

    expected = extract_headers_cna(cna_file)
    actual = extract_headers_p4(p4_file)

    print(f"Expected headers from CNA: {sorted(expected)}")
    print(f"Found headers:             {sorted(actual)}")

    missing = expected - actual
    extra = actual - expected #impossible, right?

    if missing:
        print(f"\nMissing headers: {sorted(missing)}")
        return False
    
    if extra:
        print(f"\nExtra headers: {sorted(extra)}")
        return False

    print("\nAll expected headers found.")
    return True


# Part 3: Action verification
def extract_actions_p4(p4_file: str) -> Set[str]:
    """
    Extract action names from P4 file
    """
    with open(p4_file, 'r') as f:
        content = f.read()
    
    pattern = r'action\s+(\w+)\s*\('
    actions = set(re.findall(pattern, content))
    
    return actions

def extract_actions_cna(cna_file: str) -> Set[str]:
    """
    Extract action names from CNA JSON file
    """
    with open(cna_file, 'r') as f:
        cna = json.load(f)
    
    actions = set()
    
    for comp in cna.get("composition", []):
        for action in comp.get("forwarding_actions", []):
            actions.add(clean_identifier(action["id"]))

    for svc in cna.get("services", []):
        for action in svc.get("actions", []):
            actions.add(clean_identifier(action["id"]))
    
    return actions

def verify_actions(cna_file: str, p4_file: str) -> bool:
    """
    Compare actions from CNA and P4 files
    Returns True if all actions match
    """
    print("\n Verifying actions...")

    expected = extract_actions_cna(cna_file)
    actual = extract_actions_p4(p4_file)

    print(f"Expected actions from CNA: {sorted(expected)}")
    print(f"Found actions:             {sorted(actual)}")

    missing = expected - actual
    extra = actual - expected #aint no way, right?

    if missing:
        print(f"\nMissing actions: {sorted(missing)}")
        return False
    
    if extra:
        print(f"\nExtra actions: {sorted(extra)}")
        return False
    
    print("\nAll expected actions found.")
    return True

#Part 4: Table verification
def extract_tables_p4(p4_file: str) -> Set[str]:
    """
    Extract table names from P4 file
    """
    with open(p4_file, 'r') as f:
        content = f.read()
    
    pattern = r'table\s+(\w+)\s*\{'
    tables = set(re.findall(pattern, content))
    
    return tables

def extract_tables_cna(cna_file: str) -> Set[str]:
    """
    Extract table names from CNA JSON file
    """
    with open(cna_file, 'r') as f:
        cna = json.load(f)
    
    tables = set()
    
    for comp in cna.get("composition", []):
        overlay = comp.get("overlay", "net")
        tables.add(clean_identifier(f"fwd_{overlay}_tbl"))

    for svc in cna.get("services", []):
        tables.add(clean_identifier(f"svc_{svc['id']}_policy_tbl"))

    return tables

def verify_tables(cna_file: str, p4_file: str) -> bool:
    """
    Compare tables from CNA and P4 files
    Returns True if all tables match
    """
    print("\n Verifying tables...")

    expected = extract_tables_cna(cna_file)
    actual = extract_tables_p4(p4_file)

    print(f"Expected tables from CNA: {sorted(expected)}")
    print(f"Found tables:             {sorted(actual)}")

    missing = expected - actual
    extra = actual - expected #impossible, right?

    if missing:
        print(f"\nMissing tables: {sorted(missing)}")
        return False
    
    if extra:
        print(f"\nExtra tables: {sorted(extra)}")
        return False

    print("\nAll expected tables found.")
    return True


#Part 5: Constant verification
def extract_consts_p4(p4_file: str) -> dict:
    """
    Extract constant names from P4 file
    Returns dict: {name: value}
    """
    with open(p4_file, 'r') as f:
        content = f.read()
    
    consts = {}
    pattern = r'const\s+bit<\d+>\s+(\w+)\s*=\s*([^;]+);'
    for match in re.finditer(pattern, content):
        name = match.group(1)
        value = match.group(2).strip().strip('"')  # remove quotes if present
        consts[name] = value
    
    return consts

def extract_consts_cna(cna_file: str) -> dict:
    """
    Extract constant names from CNA JSON file
    Returns dict: {name: value}
    """
    with open(cna_file, 'r') as f:
        cna = json.load(f)
    
    consts = {}
    
    for const in cna.get("consts", []):
        name = clean_identifier(const["field"])
        value = const["value"]
        consts[name] = str(value) #convert to string for comparison
    
    return consts

def verify_consts(cna_file: str, p4_file: str) -> bool:
    """
    Compare constants from CNA and P4 files
    Returns True if all constants match
    """
    print("\n Verifying constants...")

    expected = extract_consts_cna(cna_file)
    actual = extract_consts_p4(p4_file)

    print(f"Expected constants from CNA: {expected}")
    print(f"Found constants:             {actual}")

    for name, value in expected.items():
        if name not in actual:
            print(f"\nMissing constant: {name}")
            return False
        elif actual[name] != value:
            print(f"\nValue mismatch for constant {name}")
            print(f"  Expected: {value}")
            print(f"  Found:    {actual[name]}")    
            return False


    extra = set(actual.keys()) - set(expected.keys())
    if extra:
        print(f"\nExtra constants: {extra}")
        return False
    
    print("\nAll expected constants match.")
    return True

#part 6: parser transition verification

def extract_parser_transitions_p4(p4_file: str) -> list[tuple[str, str, str]]:
    """
    Extract parser transitions from P4 file
    Returns list of (from_state, to_state, trigger_value)
    trigger_value is empty string for direct transitions
    """
    with open(p4_file, 'r') as f:
        content = f.read()
    
    transitions = []
    
    # easier parsing this way
    lines = content.split('\n')
    current_state = None
    in_select = False
    
    for line in lines:
        # Check for start
        state_match = re.search(r'state\s+parse_(\w+)\s*\{', line)
        if state_match:
            current_state = state_match.group(1)
            in_select = False
            continue
        
        if current_state:
            # Check for direct transition (like "transition parse_ip2;")
            direct_match = re.search(r'transition\s+parse_(\w+)\s*;', line)
            if direct_match and 'select' not in line:
                next_state = direct_match.group(1)
                transitions.append((current_state, next_state, ""))
                current_state = None  # State ends after transition
                continue
            
            # Check for select statement start
            if 'transition select' in line:
                in_select = True
                continue
            
            if in_select:
                case_match = re.search(r'(\w+)\s*:\s*parse_(\w+)\s*;', line)
                if case_match:
                    trigger = case_match.group(1)
                    next_state = case_match.group(2)
                    transitions.append((current_state, next_state, trigger))
                
                # Check for end of select
                if '}' in line and not re.search(r'\{\s*$', line):
                    in_select = False
                    current_state = None
    
    return transitions

def extract_parser_transitions_cna(cna_file: str) -> list[tuple[str, str, str]]:
    """
    Extract parser transitions from CNA JSON file
    Returns list of tuples: (from_state, to_state, condition)
    """
    with open(cna_file, 'r') as f:
        cna = json.load(f)
    
    transitions = []

    # 1. Layering composition transitions
    for comp in cna.get("composition", []):
        if comp.get("operator") == "layering":
            underlay = clean_identifier(comp["underlay"])
            overlay = clean_identifier(comp["overlay"])
            session_id = comp.get("session_identifier", {})
            trigger_value = session_id.get("value", "")
            if trigger_value:
                transitions.append((underlay, overlay, trigger_value))
    
    # 2. Subduction composition transitions
    for comp in cna.get("composition", []):
        if comp.get("operator") == "subduction":
            underlay = clean_identifier(comp["underlay"])
            overlay = clean_identifier(comp["overlay"])
            enc_proto = comp.get("encapsulation_protocol")
            
            # Underlay -> Encapsulation protocol (GRE) on selection predicate
            for sl in comp.get("shared_links", []):
                if sl.get("direction") == "ingress":
                    pred = sl.get("selection_predicate", {})
                    trigger_value = pred.get("value", "")
                    if trigger_value and enc_proto:
                        transitions.append((underlay, clean_identifier(enc_proto), trigger_value))
            
            # Encapsulation protocol -> Overlay (direct transition, no trigger)
            if enc_proto:
                transitions.append((clean_identifier(enc_proto), overlay, ""))  # Empty = direct
    
    # 3. Session protocol transitions
    for net in cna.get("networks", []):
        net_id = clean_identifier(net["id"])
        for session in net.get("session_protocols", []):
            proto = clean_identifier(session["protocol"])
            trigger_value = session.get("indicator_value", "")
            if trigger_value:
                transitions.append((net_id, proto, trigger_value))
    
    return transitions

def verify_parser_transitions(cna_file: str, p4_file: str) -> bool:
    """
    Compare parser transitions from CNA and P4 files
    Returns True if all transitions match
    """
    print("\n Verifying parser transitions...")

    expected = extract_parser_transitions_cna(cna_file)
    actual = extract_parser_transitions_p4(p4_file)

    print(f"Expected transitions from CNA: {len(expected)}")
    for from_state, to_state, condition in expected:
        if condition:
            print(f"  {from_state} -> {to_state} [trigger={condition}]")
        else:
            print(f"  {from_state} -> {to_state} [direct]")

    print(f"Found transitions:             {len(actual)}")
    for from_state, to_state, condition in actual:
        if condition:
            print(f"  {from_state} -> {to_state} [trigger={condition}]")
        else:
            print(f"  {from_state} -> {to_state} [direct]")

    missing = []
    for exp_from, exp_to, exp_cond in expected:
        match = False
        for act_from, act_to, act_cond in actual:
            if exp_from == act_from and exp_to == act_to:
                #for direct transitions, any match is fine
                #for condtiionals, trigger must match
                if not exp_cond or exp_cond == act_cond:
                    match = True
                    break
        if not match:
            missing.append((exp_from, exp_to, exp_cond))

    if missing:
        print(f"\nMissing transitions: {len(missing)}")
        for from_state, to_state, condition in missing:
            if condition:
                print(f"  {from_state} -> {to_state} [trigger={condition}]")
            else:
                print(f"  {from_state} -> {to_state} [direct]")
        return False
    
    extra = []
    for act_from, act_to, act_cond in actual:
        match = False
        for exp_from, exp_to, exp_cond in expected:
            if act_from == exp_from and act_to == exp_to:
                if not exp_cond or exp_cond == act_cond:
                    match = True
                    break
        if not match:
            extra.append((act_from, act_to, act_cond))
    
    if extra:
        print(f"\nExtra transitions: {len(extra)}")
        for from_state, to_state, condition in extra:
            if condition:
                print(f"  {from_state} -> {to_state} [trigger={condition}]")
            else:
                print(f"  {from_state} -> {to_state} [direct]")
        return False
    
    print("\nAll expected transitions found.")
    return True

def main():
    if len(sys.argv) != 3:
        print("Usage: python verifier.py <cna.json> <p4_file>")
        print("Example: python verifier.py example.json output.p4")
        sys.exit(1)

    cna_file = sys.argv[1]
    p4_file = sys.argv[2]

    if not Path(cna_file).exists():
        print(f"File {cna_file} does not exist")
        sys.exit(1)

    if not Path(p4_file).exists():
        print(f"File {p4_file} does not exist")
        sys.exit(1)

    # do it compile?
    print("\n Step 1: Compile P4")
    compiles = compile_p4(p4_file)

    print("\n Step 2: Verify headers")
    headers_ok = verify_headers(cna_file, p4_file)

    print("\n Step 3: Verify actions")
    actions_ok = verify_actions(cna_file, p4_file)

    print("\n Step 4: Verify tables")
    tables_ok = verify_tables(cna_file, p4_file)

    print("\n Step 5: Verify constants")
    consts_ok = verify_consts(cna_file, p4_file)

    print("\n Step 6: Verify parser transitions")
    transitions_ok = verify_parser_transitions(cna_file, p4_file)

    all_ok = compiles and headers_ok and actions_ok and tables_ok and consts_ok and transitions_ok

    print("\n\n Summary:")
    print(f"   Compilation: {'SUCCESS' if compiles else 'FAILURE'}")
    print(f"   Headers:     {'SUCCESS' if headers_ok else 'FAILURE'}")
    print(f"   Actions:     {'SUCCESS' if actions_ok else 'FAILURE'}")
    print(f"   Tables:      {'SUCCESS' if tables_ok else 'FAILURE'}")
    print(f"   Constants:   {'SUCCESS' if consts_ok else 'FAILURE'}")
    print(f"   Transitions: {'SUCCESS' if transitions_ok else 'FAILURE'}")
    
    if all_ok:
        print("\nAll checks passed! P4 file is valid.")
        sys.exit(0)
    else:
        print("\nSome checks failed. Please review the output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
