#!/usr/bin/env python3
'''
    author: {{author}}
    time: {{time}}
'''
import docker.types
from pwn import *
import docker
from os import path
from pwn import *
from ctypes import *
from time import sleep
#docker run -it --rm -p 9999:9999 -p 10000:10000 --name <image_name_set> --pid=host --cap-add=SYS_PTRACE <image_name> ./run.sh
filename = "{{filename}}"
libcname = "{{libcname}}"
host = "{{host}}"
port = {{port}}
gdb_port = 10000
# 基本设置
elf = context.binary = ELF(filename)
context.terminal = ['tmux', 'neww']
context(arch = 'amd64',log_level = 'debug',os = 'linux')
container_name = 'fedora42-1' # 镜像名
run_cmd = "/bin/bash -c './run.sh'" # 容器启动命令
# 加载libc
if libcname:
    libc = ELF(libcname)
    
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

if args.DOCKER:
	client = docker.from_env()
	container = client.containers.run(
		container_name+":latest",                
		run_cmd,                   
		detach=True,                   # 后台运行容器
   		tty=True,                      # 分配伪终端    
		stdin_open=True,               # 允许容器接受输入
		ports={                        # 映射端口
			"9999/tcp": 9999,
			"10000/tcp": 10000
		},
		name= container_name,          # 容器名
		pid_mode="host",               # 设置容器共享宿主机的 PID 命名空间
    	cap_add=["SYS_PTRACE"],        # 添加容器权限
		remove=True                    # 容器停止后自动删除
	)
	p = remote(ip, port)
	processes_info = container.top()
	titles = processes_info['Titles']
	processes = [dict(zip(titles, proc)) for proc in processes_info['Processes']]
	target_proc = []
	for proc in processes:
		cmd = proc.get('CMD', '')
		exe_path = (cmd.split()[0] if cmd else '')
		exe_name = path.basename(exe_path)
		if exe_name == filename:
			target_proc.append(proc)
	idx = 0
	if len(target_proc) > 1:
		for i, v in enumerate(target_proc):
			print(f"{i} => {v}")
		idx = int(input(f"Which one:"))
	cmd = f"gdbserver :{gdb_port} --attach {target_proc[idx]['PID']}"
	exec_instance = container.exec_run(cmd, detach=True, tty=True)
	run_in_new_terminal(f"gdb -ex \"target remote {ip}:{gdb_port}\"")
else:
	p = remote(ip, port)
# Your exploit here

p.interactive()