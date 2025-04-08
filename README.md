# cpwn
A tool inspired by [pwninit](https://github.com/io12/pwninit) and [glibc-all-in-one](https://github.com/matrix1001/glibc-all-in-one) to initialize pwn game exploit enviroment.

## Features
- Automatically download and extract glibc, debug symbols, source etc.
- Generate the exploit using the [jinja2]() template.
- Provides exploit templates that support display debug symbols and source code.
- Flexible way to modify [configuration files](./config.json).
- Automatically initializes the kernel exploitation environment.
- Debug process in docker container by [template script](./template.py).
## Setup
If you are using Ubuntu, you can just set as follwing:
```sh
git clone https://github.com/GeekCmore/cpwn
cd cpwn
./setup.sh
```
If you are using other OS, please to modify the [setup.sh](./setup.sh) to fit your enviroment. Take ease, that's not take you long time. Test only in Ubuntu22.04 and Ubuntu24.04, Please send me an issue if you have any questions.
## Usage
### fetch
If you first use cpwn, just `fetch` the glibc versions maintain in https://launchpad.net/ubuntu/. The download speed depends on your network environment, and I'll expand cpwn to fit other verions and mirrors.
```sh
cpwn fetch
```
If you run into problems during fetch, just add `--force` options to forece update the pkgs.
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

### kernel

This command will extract the kernel image and the root filesystem, then generate vmlinux, .gdbinit, exp.c, debug.sh files for exploit devloping.

```sh
$ cpwn kernel ./run.sh ./rootfs.cpio ./bzImage
[+] Start generating vmlinux.
[+] Kernel successfully decompressed in-memory (the offsets that follow will be given relative to the decompressed binary)
[+] Version string: Linux version 6.1.73 (root@xxxx) (gcc (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0, GNU ld (GNU Binutils for Ubuntu) 2.38) # SMP PREEMPT_DYNAMIC 
[+] Guessed architecture: x86_64 successfully in 2.10 seconds
[+] Found kallsyms_token_table at file offset 0x01762190
[+] Found kallsyms_token_index at file offset 0x01762500
[+] Found kallsyms_markers at file offset 0x017138b8
[+] Found kallsyms_names at file offset 0x015b1838
[+] Found kallsyms_num_syms at file offset 0x015b1830
[i] Negative offsets overall: 99.7338 %
[i] Null addresses overall: 0.00187454 %
[+] Found kallsyms_offsets at file offset 0x01549510
[+] Successfully wrote the new ELF kernel to /home/geekcmore/ctf/pwn/games/ctfpunk/Linux_kernel/Heap/HeapSpray/attachment/exploit/vmlinux
[+] Successfully!
[+] Start extract cpio.
5097 blocks
[+] Successfully!
[+] Walk for kpm files
[*] Found 1 /home/geekcmore/ctf/pwn/games/ctfpunk/Linux_kernel/Heap/HeapSpray/attachment/exploit/extracted/vuln.ko
[+] Start generate gdbscript at exploit/.gdbinit.
[+] Successfully!
[+] Start generate debug script.
[+] Create run.sh!
[+] Create debug.sh!
[+] Finish.
[+] Start generate exploit script.
[+] Successfully!
```

After that, we just `cd ./exploit`, develop your `exp.c`, then run `./debug.sh` for debug, `./run.sh` for test with the `exp.c` compiled and the `rootfs.cpio`  packed automatically. What you  should do is just run `./exp` in the Vm started by qemu.

```
$ ls
debug.sh  exp.c  extracted  run.sh  vmlinux  vuln.ko
```

### Template

The template is as follows, you can replace it as you like. But with this template, you can:
- run `./exp.py GDB` to pop a gdb window(change the `context.terminal = ['tmux', 'neww']` to  fit your terminal) with debug symbols and source of glibc.
- run `./exp.py REMOTE` to attack the remote aircraft.
- run `./exp.py DEBUG` to turn on debug log mode of pwntools.
- run `./exp.py DOCKER` to start a remote process and pop up a gdb terminal to debug.
```py
#!/usr/bin/env python3

'''
    author: {{author}}
    time: {{time}}
'''
from pwn import *

filename = "{{filename}}"
libcname = "{{libcname}}"
host = "{{host}}"
port = {{port}}
container_id = ""
proc_name = ""
elf = context.binary = ELF(filename)
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
    elif args.DOCKER:
        import docker
        from os import path
        p = remote(ip, port)
        client = docker.from_env()
        container = client.containers.get(container_id=container_id)
        processes_info = container.top()
        titles = processes_info['Titles']
        processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
        target_proc = []
        for proc in processes:
            cmd = proc.get('CMD', '')
            exe_path = cmd.split()[0] if cmd else ''
            exe_name = path.basename(exe_path)
            if exe_name == proc_name:
                target_proc.append(proc)
        idx = 0
        if len(target_proc) > 1:
            for i, v in enumerate(target_proc):
                print(f"{i} => {v}")
            idx = int(input(f"Which one:"))
        run_in_new_terminal(["sudo", "gdb", "-p", target_proc[idx]['PID']])
        return p
    else:
        return process(elf.path)

p = start()

# Your exploit here

p.interactive()
```

And the  [kernel/exploit/exp.c](kernel/exploit/exp.c) is the template for kernel exploit.

## config

These configuration items are straightforward, just try them.
```json
{
    "author": "GeekCmore",
    "template": "~/.config/cpwn/exp_template.py",
    "script_name": "exp.py",
    "file_path": "~/.config/cpwn/pkgs",
    "kernel_file_path": "~/.config/cpwn/kernel_exploit",
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
    "threads": 10,
    "force": false
}
```