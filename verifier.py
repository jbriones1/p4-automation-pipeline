#!/usr/bin/env python3

import subprocess
import json
import re
import sys
from pathlib import Path
from typing import Set

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

def main():
    if len(sys.argv) != 2:
        print("Usage: python verifier.py <p4_file>")
        print("Example: python verifier.py output.p4")
        sys.exit(1)

    p4_file = sys.argv[1]

    if not Path(p4_file).exists():
        print(f"File {p4_file} does not exist")
        sys.exit(1)

    # do it compile?
    success = compile_p4(p4_file)

    sys.exit(0 if success else 1)
    

if __name__ == "__main__":
    main()