/* Tiny real i386 process for verifying that compat syscalls are not decoded
 * with the amd64 syscall table. No libc or multilib runtime is needed. */
.section .text
.global _start
_start:
    mov $20, %eax
    int $0x80
    mov $1, %eax
    xor %ebx, %ebx
    int $0x80
.section .note.GNU-stack,"",@progbits
