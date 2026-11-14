#!/usr/bin/env python3
"""Pin every exec.allow entry of a policy to the sha256 of the binary on THIS machine.

    python3 tools/policy_pin.py policy/policy.hardened.yaml > policy/policy.pinned.yaml

Bare list items `- /usr/bin/ls` inside an `exec: allow:` block become
`- {path: /usr/bin/ls, sha256: <hash>}`.  Comments and layout are preserved (line-based edit).
Hashes are per machine and change when the package is updated: re-run after `apt upgrade`, and
commit the pinned file only for a fixed, documented image.  kgctl refuses to start an agent whose
binary no longer matches its pin."""
import hashlib
import os
import re
import sys

ITEM = re.compile(r"^(\s*)- (/[^\s#]+)(\s*#.*)?$")


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 20), b""):
            h.update(c)
    return h.hexdigest()


def pin(text):
    out, in_exec, in_allow, count = [], False, False, 0
    for line in text.splitlines():
        s = line.strip()
        indent = len(line) - len(line.lstrip())
        if re.match(r"^exec:\s*(#.*)?$", s):
            in_exec, in_allow = True, False
            exec_indent = indent
        elif in_exec and re.match(r"^allow:\s*(#.*)?$", s):
            in_allow, allow_indent = True, indent
        elif (in_allow and s and not s.startswith("#") and not s.startswith("-") and indent <= allow_indent) or \
                (in_exec and s and not s.startswith("#") and indent <= exec_indent and not s.startswith("exec")):
            in_allow = in_allow and indent > allow_indent
            in_exec = in_exec and indent > exec_indent
        m = ITEM.match(line) if in_allow else None
        if m:
            real = os.path.realpath(m.group(2))
            if not os.path.isfile(real):
                raise SystemExit(f"policy_pin: {m.group(2)} does not exist on this machine")
            line = f"{m.group(1)}- {{path: {m.group(2)}, sha256: {sha(real)}}}{m.group(3) or ''}"
            count += 1
        out.append(line)
    if not count:
        raise SystemExit("policy_pin: found no exec.allow entries to pin")
    sys.stderr.write(f"pinned {count} executables\n")
    return "\n".join(out) + "\n"


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    sys.stdout.write(pin(open(sys.argv[1]).read()))
