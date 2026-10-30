/* loadprobe: minimal static aarch64 ELF that tries finit_module() on argv[1]
 * and exits with the errno.
 *
 * It gets written into the page cache of /vendor/bin/toybox_vendor (label
 * vendor_toolbox_exec_30_0, the only exec type vendor_modprobe is allowed to
 * use) so that the kernel's exec runs OUR code in that domain -- which is what
 * lets us see the real errno from the module loader instead of guessing from
 * insmod's unreadable stderr.
 *
 * exit codes: 0 = loaded, 1..255 = errno, 0x80|errno = couldn't open argv[1],
 *             200 = no argument.
 */
    .arch armv8-a

    .equ SYS_openat,       56
    .equ SYS_finit_module, 273
    .equ SYS_exit,         93
    .equ AT_FDCWD,        -100

    .text
    .global _start
_start:
    ldr     x0, [sp]                // argc
    cmp     x0, #2
    b.lt    L_noarg

    ldr     x1, [sp, #16]           // argv[1] = module path
    mov     x0, AT_FDCWD
    mov     x2, #0                  // O_RDONLY
    mov     x3, #0
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, L_openfail

    adr     x1, empty_arg
    mov     x2, #0
    mov     x8, #SYS_finit_module
    svc     0
    cbz     x0, L_ok                // 0 = module loaded
    neg     x0, x0                  // errno
    b       L_exit

L_ok:
    mov     x0, #0
    b       L_exit

L_openfail:
    neg     x0, x0
    orr     x0, x0, #0x80
    b       L_exit

L_noarg:
    mov     x0, #200
L_exit:
    mov     x8, #SYS_exit
    svc     0

empty_arg:
    .asciz ""
