#!/usr/bin/env python3
"""Insert BakaSU manual-hook call sites into a 4.19 kernel tree.

The hooks are declared in the module and called from the syscall paths; this is
what bakasu.org/guide/manual-integrate describes.  Anchors are matched loosely
so the script works across vendor trees that differ in whitespace.
"""
import re
import sys
import pathlib

ROOT = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".")
DECL = """
#ifdef CONFIG_KSU
extern int ksu_handle_execve(int *fd, const char *filename, void *argv,
			     void *envp, int *flags);
extern int ksu_handle_faccessat(int *dfd, const char __user **filename_user,
				int *mode, int *__unused_flags);
extern int ksu_handle_stat(int *dfd, const char __user **filename_user,
			   int *flags);
extern int ksu_handle_newfstat_ret(unsigned int *fd, struct stat __user **statbuf);
extern int ksu_handle_fstat64_ret(unsigned int *fd, struct stat64 __user **statbuf);
extern int ksu_handle_sys_reboot(int magic1, int magic2, unsigned int cmd, void __user **arg);
#endif
"""

patched = []


def insert(path, anchor_re, snippet, before=True, decl=True):
    p = ROOT / path
    if not p.exists():
        print(f"skip {path}: missing")
        return False
    src = p.read_text(errors="surrogateescape")
    if "ksu_handle_" in src and snippet.strip() in src:
        print(f"skip {path}: already patched")
        return True
    m = re.search(anchor_re, src, re.M)
    if not m:
        print(f"FAIL {path}: anchor {anchor_re!r} not found")
        return False
    pos = m.start() if before else m.end()
    src = src[:pos] + snippet + src[pos:]
    if decl:
        # declaration goes right after the last #include block
        inc = list(re.finditer(r"^#include .*$", src, re.M))
        if inc:
            at = inc[-1].end()
            src = src[:at] + "\n" + DECL + src[at:]
    p.write_text(src, errors="surrogateescape")
    patched.append(path)
    print(f"patched {path}")
    return True


# fs/exec.c: do_execveat_common() entry
insert("fs/exec.c",
       r"^static int do_execveat_common\(",
       """
#ifdef CONFIG_KSU
	ksu_handle_execve(&fd, filename ? filename->name : NULL,
			  (void *)&argv, (void *)&envp, &flags);
#endif
""")

# fs/open.c: do_faccessat() entry
insert("fs/open.c",
       r"^static (?:long|int) do_faccessat\(",
       """
#ifdef CONFIG_KSU
	ksu_handle_faccessat(&dfd, &filename, &mode, NULL);
#endif
""")

# fs/stat.c: vfs_statx() / vfs_fstatat() entries
insert("fs/stat.c",
       r"^int vfs_statx\(",
       """
#ifdef CONFIG_KSU
	ksu_handle_stat(&dfd, &filename, &flags);
#endif
""")
insert("fs/stat.c",
       r"^int vfs_fstatat\(",
       """
#ifdef CONFIG_KSU
	ksu_handle_stat(&dfd, &filename, &flags);
#endif
""")

# kernel/reboot.c: SYSCALL_DEFINE4(reboot)
insert("kernel/reboot.c",
       r"^SYSCALL_DEFINE4\(reboot,",
       """
#ifdef CONFIG_KSU
	ksu_handle_sys_reboot(magic1, magic2, cmd, &arg);
#endif
""")

print("patched files:", patched)
