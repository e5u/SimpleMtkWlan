#!/bin/sh
# Print the SimpleMtkWlan persistent debug log from IORegistry.
set -eu
echo "loaded: $(kmutil showloaded 2>/dev/null | grep -oE "com.(laobamac.SimpleMtkWlan|flxxxxddd.AirportMtkWlan).*" )"
echo "instances: SimpleMtkWlan=$(ioclasscount SimpleMtkWlan 2>/dev/null) AirportItlwm=$(ioclasscount AirportItlwm 2>/dev/null)"
tmp="$(mktemp /tmp/mtklog.XXXXXXXX.plist)"
trap 'rm -f "$tmp"' EXIT
ioreg -a -l -r -c IOPCIDevice > "$tmp"
python3 -I - "$tmp" <<'PY'
import plistlib
import sys

with open(sys.argv[1], "rb") as stream:
    root = plistlib.load(stream)

logs = []

def walk(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "MtkDebugLog":
                if isinstance(child, bytes):
                    child = child.decode("utf-8", "replace")
                elif isinstance(child, list):
                    child = "\n".join(str(item) for item in child)
                logs.append(str(child))
            walk(child)
    elif isinstance(value, list):
        for child in value:
            walk(child)

walk(root)
if not logs:
    raise SystemExit("MtkDebugLog not found")
sys.stdout.write("\n".join(logs))
if not logs[-1].endswith("\n"):
    sys.stdout.write("\n")
PY
