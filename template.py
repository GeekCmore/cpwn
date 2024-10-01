#!/usr/bin/env python

'''
    author: {{author}}
    time: {{time}}
'''
from pwn import *

filename = "{{filename}}"
libcname = "{{libcname}}"
host = "{{host}}"
port = {{port}}
elf = context.binary = ELF(filename)
context.terminal = ['tmux', 'neww']
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

p = start()

# Your exploit here

p.interactive()
