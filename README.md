# cpwn
A tool inspired by [pwninit](https://github.com/io12/pwninit) and [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one) to initialize pwn game exploit enviroment.

## Features
- Automatically download and extract glibc, debug symbols, source etc.
- Generate the exploit using the [jinja2]() template.
- Provides exploit templates that support display debug symbols and source code.
- Flexible way to modify [configuration files](./config.json).

## Setup
If you are using Ubuntu, you can just set as follwing:
```sh
git clone https://github.com/GeekCmore/cpwn
cd cpwn
sh ./setup
```
If you are using other OS, please to modify the [setup.sh](./setup.sh) to fit your enviroment. Take ease, that's not take you long time.
## Usage
### fetch
If you first use cpwn, just `fetch` the glibc versions maintain in https://launchpad.net/ubuntu/. The download speed depends on your network environment, and I'll expand cpwn to fit other verions and mirrors.
```sh
cpwn fetch
```
### init
After fetch, everything is finish. What you need to do is `init` in your work directory with your pwn file patchedless like this:
```sh
$ tree
.
├── pwn
0 directories, 1 files
$ ldd pwn
        linux-vdso.so.1 (0x00007ffce7599000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f96427c0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f9642a4e000)
$ cpwn init
Detect excutable file pwn
No libc file find in your workdir.
Do you want to list the table of versions in your enviroment?(y/n)y
+-----+------------------+
| Idx |     Version      |
+-----+------------------+
|  0  | 2.23-0ubuntu11.3 |
+-----+------------------+
|  1  |  2.23-0ubuntu3   |
+-----+------------------+
|  2  |  2.27-3ubuntu1   |
+-----+------------------+
|  3  | 2.27-3ubuntu1.5  |
+-----+------------------+
|  4  | 2.27-3ubuntu1.6  |
+-----+------------------+
|  5  |  2.31-0ubuntu9   |
+-----+------------------+
|  6  | 2.31-0ubuntu9.16 |
+-----+------------------+
|  7  |  2.35-0ubuntu3   |
+-----+------------------+
|  8  | 2.35-0ubuntu3.8  |
+-----+------------------+
|  9  |  2.39-0ubuntu8   |
+-----+------------------+
|  10 | 2.39-0ubuntu8.3  |
+-----+------------------+
|  11 |  2.40-1ubuntu1   |
+-----+------------------+
Choose the version you wnat to modify:0
Patch pwn to pwn_patched successfully.
Generate script exp.py successfully.
```
Or you have libc in your directory, cpwn can detect it automatically:
```sh
$ tree
.
├── ld-linux-x86-64.so.2
├── libc.so.6
├── pwn
$ cpwn init
Detect libc.so.6 file libc-2.23.so
Detect excutable file orange_cat_diary
Patch pwn to pwn_patched successfully.
Generate script exp.py successfully.
```

### Template
The template is as follows, you can replace it as you like. But with this template, you can:
- run `./exp.py GDB` to pop a gdb window(change the `context.terminal = ['tmux', 'neww']` to  fit your terminal) with debug symbols and source of glibc.
- run `./exp.py REMOTE` to attack the remote aircraft.
- run `./exp.py DEBUG` to turn on debug log mode of pwntools.
```py
#!/usr/bin/python3

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

```

## config
These configuration items are straightforward, just try them.
```json
{
    "author": "GeekCmore",
    "template": "~/.config/cpwn/exp_template.py",
    "script_name": "exp.py",
    "file_path": "~/.config/cpwn/pkgs",
    "mirror": "",
    "archs": [
        "amd64",
        "i386"
    ],
    "pkgs": [
        "libc6",
        "libc6-dbg",
        "glibc-source"
    ],
    "threads": 10
}
```