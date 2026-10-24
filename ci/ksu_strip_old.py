#!/usr/bin/env python3
"""Strip a pre-existing KernelSU integration out of a kernel tree.

Vendor/LineageOS trees sometimes carry hooks from an older KernelSU (or a
previous ReSukiSU attempt).  They conflict with the module we are about to
build, so every `#ifdef CONFIG_KSU ... #endif` block that mentions a ksu_
symbol is removed, together with stray calls to the old helpers.

Run this BEFORE ci/ksu_hooks.py, which then installs the hooks BakaSU expects.
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")

# Files worth scanning: the syscall paths KernelSU hooks live in.
TARGETS = ["fs", "security", "kernel", "mm", "drivers", "include"]

# Old helper names that must disappear.  ksu_handle_* are re-added by
# ci/ksu_hooks.py, so they are stripped here too and patched back cleanly.
OLD = re.compile(r"\bksu_[a-z0-9_]+\b")

BLOCK = re.compile(
    r"^[ \t]*#if(?:def|ndef)?[ \t]+CONFIG_KSU[A-Z_]*\b.*?^[ \t]*#endif[^\n]*\n",
    re.M | re.S,
)


def strip_file(path: pathlib.Path) -> bool:
    try:
        src = path.read_text(errors="surrogateescape")
    except OSError:
        return False
    if "ksu_" not in src:
        return False

    orig = src

    # 1) remove whole #ifdef CONFIG_KSU blocks that reference ksu_ helpers
    def repl(m):
        block = m.group(0)
        if OLD.search(block):
            return ""
        return block

    src = BLOCK.sub(repl, src)

    # 2) remove single-line calls to old helpers that were not guarded
    src = re.sub(r"^[ \t]*ksu_[a-z0-9_]+\([^;\n]*\);[ \t]*\n", "", src, flags=re.M)
    # ... and their declarations
    src = re.sub(r"^[ \t]*(?:extern\s+)?[A-Za-z_][\w \t\*]*\bksu_[a-z0-9_]+\([^;\n]*\);[ \t]*\n", "", src, flags=re.M)

    if src != orig:
        path.write_text(src, errors="surrogateescape")
        return True
    return False


changed = []
for top in TARGETS:
    base = ROOT / top
    if not base.exists():
        continue
    for p in base.rglob("*"):
        if p.suffix not in (".c", ".h"):
            continue
        if strip_file(p):
            changed.append(str(p.relative_to(ROOT)))

print("stripped old KSU hooks from:", len(changed), "file(s)")
for c in changed[:40]:
    print("  ", c)

# Report what is left, so the build log shows whether anything survived.
left = []
for top in TARGETS:
    base = ROOT / top
    if not base.exists():
        continue
    for p in base.rglob("*"):
        if p.suffix in (".c", ".h") and "ksu_" in p.read_text(errors="surrogateescape"):
            left.append(str(p.relative_to(ROOT)))
print("files still mentioning ksu_:", len(left))
for c in left[:40]:
    print("  ", c)
