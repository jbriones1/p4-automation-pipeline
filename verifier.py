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

def compile_p4(p4_file: str) -> bool:
    """
    Try to compile a P4 file using p4c
    Returns True if compilation succeeds, False otherwise
    """
    print(f"Compiling {p4_file}")
    
    # create build directory if it don't exist
    build_dir = Path("build")
    build_dir.mkdir(exist_ok=True)
    
    # output JSON (jayson?)
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
        # run dat shit
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

    #so no head?
    if missing:
        print(f"\nMissing headers: {sorted(missing)}")
        return False
    else:
        print("\nAll expected headers found.")

    if extra:
        print(f"\nExtra headers: {sorted(extra)}") #should be ok?

    return True

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
    else:
        print("\nAll expected actions found.")

    if extra:
        print(f"\nExtra actions: {sorted(extra)}") #should be ok?

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

    all_ok = compiles and headers_ok and actions_ok

    print(f"   Compilation: {'SUCCESS' if compiles else 'FAILURE'}")
    print(f"   Headers:     {'SUCCESS' if headers_ok else 'FAILURE'}")
    print(f"   Actions:     {'SUCCESS' if actions_ok else 'FAILURE'}")
    
    if all_ok:
        print("\nAll checks passed! P4 file is valid.")
        sys.exit(0)
    else:
        print("\nSome checks failed. Please review the output above.")
        sys.exit(1)

if __name__ == "__main__":
    main()
