# test_scan.py
import sys
import os
from pathlib import Path
from services.analysis import Analyzer

if len(sys.argv) < 2:
    print("Usage: python test_scan.py ")
    sys.exit(1)

target_path = os.path.abspath(sys.argv[1])

if not os.path.exists(target_path):
    print(f"[-] Error: Path does not exist: {target_path}")
    sys.exit(1)

# Set up test output folder inside /data/uploads
job_id = "cli-test"
job_path = f"/data/uploads/{job_id}"
os.makedirs(job_path, exist_ok=True)

print(f"[*] Target:   {target_path}")
print(f"[*] Out Dir:  {job_path}")
print("[*] Running Analyzer...\n")

analyzer = Analyzer(job_id=job_id, job_path=job_path)
analyzer.analyze(target_path)

print("[+] Analysis complete! Here are the outputs generated:\n" + "="*50)

# Dump out whatever text files the analyzer generated
for filename in ["analysis.txt", "secrets.txt", "codesign.txt", "hardened.txt"]:
    file_path = os.path.join(job_path, filename)
    if os.path.exists(file_path):
        print(f"\n--- {filename} ---")
        with open(file_path, "r", errors="ignore") as f:
            content = f.read().strip()
            print(content if content else "")

# Print the first 20 lines of strings.txt so it doesn't flood terminal
strings_path = os.path.join(job_path, "strings.txt")
if os.path.exists(strings_path):
    print(f"\n--- strings.txt (first 20 lines) ---")
    with open(strings_path, "r", errors="ignore") as f:
        lines = [f.readline().strip() for _ in range(20)]
        print("\n".join(filter(None, lines)))