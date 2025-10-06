#!/usr/bin/env python3
'''
    author: {{author}}
    time: {{time}}
'''
from pwn import *
from time import sleep
filename = "{{filename}}"
libcname = "{{libcname}}"
host = "{{host}}"
port = {{port}}
elf = context.binary = ELF(filename)
context.terminal = ['tmux', 'neww']
context(arch = 'amd64',log_level = 'debug',os = 'linux')
if libcname:
    libc = ELF(libcname)
gs = '''
b main
{% if debug_file_directory %}set debug-file-directory {{debug_file_directory}}{%endif%}
{% if source_dircetory %}set directories {{source_dircetory}}{%endif%}
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript = gs)
    elif args.REMOTE:
        return remote(host, port)
    else:
        return process(elf.path)
#---------------------------------------------------#
r = lambda x:p.recv(x)
rl = lambda:p.recvline(keepends=True)
til = lambda x:p.recvuntil(x,drop=True) 
s = lambda x:p.send(x)
sl = lambda x:p.sendline(x)
sa = lambda x,y:p.sendafter(x,y)
sla = lambda x,y:p.sendlineafter(x,y)
suc = lambda x,y:success(x+" -> "+y)
#---------------------------------------------------#
def db() : 
    gdb.attach(p)
    pause()

p = start()

# Your exploit here

p.interactive()
