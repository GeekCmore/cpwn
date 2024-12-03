#!/usr/bin/env python3
from enum import Enum
from tqdm import tqdm
import subprocess
import requests
import click
import os
import json
import magic
import shutil
from pwn import ELF
from prettytable import PrettyTable
from datetime import datetime
from bs4 import BeautifulSoup


# structure
class BaseFile(Enum):
    EXECUTABLE = "executable"
    LIBC = "libc.so.6"
    LD = "ld.so"
    SRC = "src"
    DBG = "dbg"


# Auxiliary functions
def log_base(msg, color):
    click.echo(click.style(msg, fg=color))


def log_info(msg):
    log_base("[+] " + msg, "blue")


def log_success(msg):
    log_base("[*] " + msg, "green")


def log_error(msg):
    log_base("[-] " + msg, "red")
    exit(-1)


def prompt(msg: str):
    tmp = input(msg + " (N/n to refuse, others to argee): ")
    return tmp != "n" and tmp != "N"


def download_and_extract(file):
    try:
        url = file[0]
        deb_filename = file[1]
        extract_path = ".".join(deb_filename.split(".")[:-1])
        tmp_file = deb_filename + ".download"
        if not os.path.exists(deb_filename) or config["force"]:
            resp = requests.get(url, stream=True)
            total = int(resp.headers.get("content-length", 0))
            with open(tmp_file, "wb") as file, tqdm(
                desc=os.path.basename(deb_filename),
                total=total,
                unit="iB",
                unit_scale=True,
                unit_divisor=1024,
                ascii=True,
                leave=False,
            ) as bar:
                for data in resp.iter_content(chunk_size=1024):
                    size = file.write(data)
                    bar.update(size)
            subprocess.run(
                ["mv", tmp_file, deb_filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        if not os.path.exists(extract_path):
            subprocess.run(
                ["dpkg", "-x", deb_filename, extract_path],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            subprocess.run(f'chmod -R +x "{extract_path}"', text=True, shell=True)

        if "glibc-source" in extract_path:
            source_path = os.path.join(extract_path, "usr/src/glibc/")
            version_name = extract_path.split("glibc-source_")[1][:4]
            subprocess.run(
                [
                    "tar",
                    "-xvf",
                    os.path.join(source_path, f"glibc-{version_name}.tar.xz"),
                    "-C",
                    source_path,
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
        return "Successfully!"
    except Exception as e:
        subprocess.run(
            ["rm", "-f", tmp_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        subprocess.run(
            ["rm", "-f", deb_filename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        return f"Error: {e}"


def download_give_version_arch(version, arch):
    download_list = generate_expect_download_list(version, arch)
    multi_download(download_list)


def multi_download(download_list):
    from concurrent.futures import ThreadPoolExecutor, as_completed

    cnt = 0
    with ThreadPoolExecutor(max_workers=config["threads"]) as executor:
        future_to_file = {
            executor.submit(download_and_extract, file): file for file in download_list
        }
        for future in tqdm(
            iterable=as_completed(future_to_file),
            desc="All to download",
            total=len(download_list),
            ascii=True,
            leave=False,
        ):
            file = future_to_file[future]
            try:
                download_list.remove(file)
                cnt += 1
            except Exception as exc:
                log_error(
                    click.style(
                        f"Fetch {os.path.basename(file[1])} generated an exception: {exc}",
                        fg="red",
                    )
                )
    log_success(click.style(f"Successfully download {cnt} files.", fg="blue"))
    if len(download_list) != 0:
        log_error(f"These download or extract failed: {download_list}")


def fetch_archs_by_version(version: str) -> dict:
    """
    use the given version of glibc to fetch arch id
    such as https://launchpad.net/ubuntu/+source/glibc/2.35-0ubuntu3.7
    """
    base_url = "https://launchpad.net"
    url = base_url + "/ubuntu/+source/glibc/" + version
    div = BeautifulSoup(requests.get(url).text, "lxml").find_all(
        "div", {"id": "source-builds"}
    )[0]
    arch_idx = {}
    for a in div.find_all("a")[1:]:
        arch_idx[a.get_text()] = (
            a["href"] if "http" in a["href"] else base_url + a["href"]
        )
    return arch_idx


def fetch_remote_files(url):
    """
    fetch all files by build id
    such as https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/28112201
    """
    built_files = {}
    # built_files_url = "https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/" + id
    soup = BeautifulSoup(requests.get(url).text, "lxml")
    cpkgs = soup.find_all("div", {"id": "files", "class": "portlet"})[0].find_all(
        "a", {"class": "sprite download"}
    )
    for cpkg in cpkgs:
        cpkg_name = cpkg.get_text().strip()
        cpkg_url = cpkg["href"]
        built_files[cpkg_name] = cpkg_url
    return built_files


def generate_expect_download_list(version, arch) -> list:
    expect_pkgs = []
    for expect_pkg in config["pkgs"]:
        if expect_pkg == "glibc-source":
            if arch == "amd64":  # only amd64 has glibc-source_xxxxxx_all.deb
                expect_pkgs.append(f"{expect_pkg}_{version}_all.deb")
        else:
            expect_pkgs.append(f"{expect_pkg}_{version}_{arch}.deb")
    arch_urls = fetch_archs_by_version(version)
    remote_files_map = fetch_remote_files(arch_urls[arch])
    arch_store_path = dir_from_version_arch(version, arch)
    download_list = []
    for expect_file in expect_pkgs:
        expect_file_path = os.path.join(arch_store_path, expect_file)
        download_list.append((remote_files_map[expect_file], expect_file_path))
    return download_list


def dir_from_version_arch(version, arch):
    store_path = os.path.join(config["file_path"], version)
    arch_path = os.path.join(store_path, arch)
    if not os.path.exists(arch_path):
        os.makedirs(arch_path)
    return arch_path


def detect(target_files: dict = {}) -> dict:
    """
    Detect current workdir to determine target files.
    """
    pwd = os.getcwd()
    mime = magic.Magic(mime=True)
    for k, v in target_files.items():
        log_info(f"You choose {v} as your {k} file, skip detecting it.")

    for filename in os.listdir(pwd):
        file_path = os.path.join(pwd, filename)
        if os.path.isdir(file_path):
            continue
        file_type = mime.from_file(file_path)
        if (
            file_type == "application/x-pie-executable"
            or file_type == "application/x-executable"
        ):
            if BaseFile.EXECUTABLE not in target_files:
                if prompt(f"Executable {filename} found, use it as your target?"):
                    target_files[BaseFile.EXECUTABLE] = file_path
        elif file_type == "application/x-sharedlib":
            if "libc" in file_path:
                target_files[BaseFile.LIBC] = file_path
                log_success(f"Detect target libc.so.6 file {filename}")
            elif "ld" in file_path:
                target_files[BaseFile.LD] = file_path
                log_success(f"Detect target ld.so file {filename}")
            else:
                target_files[os.path.basename(file_path)] = file_path
                log_success(f"Detect ohter shared lib {filename}")
    if BaseFile.EXECUTABLE not in target_files:
        log_error("Failed to detect executable file!")
    return target_files


def get_version_by_libc(file):
    result = subprocess.run(
        f'strings "{file}" | grep "Ubuntu GLIBC" | tail -n 1',
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        shell=True,
    )
    return result.stdout.split("(Ubuntu GLIBC ")[1].split(")")[0]


def get_glibc_files(version: str, arch: str) -> dict:
    """
    get version directory by glibc version and executable arch.
    """
    ld_name_map = {
        "amd64": "x86_64-linux-gnu/ld-linux-x86-64.so.2",
        "i386": "i386-linux-gnu/ld-linux.so.2",
    }
    libc_name_map = {
        "amd64": "x86_64-linux-gnu/libc.so.6",
        "i386": "i386-linux-gnu/libc.so.6",
    }
    glibc_files = {}
    expect_dir = os.path.join(config["file_path"], version)
    if float(version[0:4]) >= 2.39:
        glibc_files[BaseFile.LIBC] = os.path.join(
            expect_dir,
            f"{arch}/libc6_{version}_{arch}/usr/lib/{libc_name_map[arch]}",
        )
        glibc_files[BaseFile.LD] = os.path.join(
            expect_dir,
            f"{arch}/libc6_{version}_{arch}/usr/lib/{ld_name_map[arch]}",
        )
    else:
        glibc_files[BaseFile.LIBC] = os.path.join(
            expect_dir,
            f"{arch}/libc6_{version}_{arch}/lib/{libc_name_map[arch]}",
        )
        glibc_files[BaseFile.LD] = os.path.join(
            expect_dir,
            f"{arch}/libc6_{version}_{arch}/lib/{ld_name_map[arch]}",
        )
    glibc_files[BaseFile.DBG] = os.path.join(
        expect_dir, f"{arch}/libc6-dbg_{version}_{arch}/usr/lib/debug"
    )
    glibc_files[BaseFile.SRC] = os.path.join(
        expect_dir,
        f"amd64/glibc-source_{version}_all/usr/src/glibc/glibc-{version[0:4]}",
    )
    # for k, v in glibc_files.items():
    #     if not os.path.exists(v):
    #         del glibc_files[k]
    return glibc_files


def choose_version():
    table = PrettyTable(["Idx", "Version"])
    table.hrules = True
    lib_path = os.path.join(config["file_path"])
    libc_list = []
    for dir in os.listdir(lib_path):
        libc_list.append(dir)
    libc_list = sorted(libc_list, key=lambda x: x)
    for i, row in enumerate(libc_list):
        table.add_row([str(i), row])
    log_info(table)
    idx = int(input("Choose the version you wnat to modify:"))
    return libc_list[idx]


def copy(filename: str, filecopy: str) -> str:
    if not os.path.exists(filename):
        click.echo(f"[-] Error: {filename} dosen't exists!")
    elif os.path.exists(filecopy):
        prompt(f"The duplicate {filecopy} exists. Do you want to cover it?")
    else:
        shutil.copy(filename, filecopy)


# command handle functions


def do_patch(target_files):
    """
    Patch the target executable file, and search for
    """
    # precheck
    prepared_files = {}
    target_excutable = target_files[BaseFile.EXECUTABLE] + "_patched"
    arch = ELF(target_files[BaseFile.EXECUTABLE]).arch
    if BaseFile.LIBC not in target_files:
        log_info("No libc file find in your workdir.")
        if not prompt("Do you want to list the table of versions in your enviroment?"):
            exit(0)
        version = choose_version()
    else:
        version = get_version_by_libc(target_files[BaseFile.LIBC])
    glibc_files = get_glibc_files(version, arch)
    if not os.path.exists(glibc_files[BaseFile.LIBC]) or not os.path.exists(
        glibc_files[BaseFile.LD]
    ):
        if prompt(
            f"You don't have {version} version of glibc, do you want to download?"
        ):
            log_info("Start downloading...")
            download_give_version_arch(version, arch)
        else:
            log_error("No suitable glibc!")
        prepared_files[BaseFile.LIBC] = glibc_files[BaseFile.LIBC]
    prepared_files[BaseFile.LIBC] = glibc_files[BaseFile.LIBC]
    prepared_files[BaseFile.LD] = glibc_files[BaseFile.LD]
    # copy and patch
    copy(target_files[BaseFile.EXECUTABLE], target_excutable)
    subprocess.run(f'chmod +x "{target_excutable}"', text=True, shell=True)
    subprocess.run(
        f'chmod +x "{target_files[BaseFile.EXECUTABLE]}"', text=True, shell=True
    )
    subprocess.run(
        f'patchelf --replace-needed libc.so.6 "{glibc_files[BaseFile.LIBC]}" "{target_excutable}"',
        text=True,
        shell=True,
    )
    subprocess.run(
        f'patchelf --set-interpreter "{glibc_files[BaseFile.LD]}" "{target_excutable}"',
        text=True,
        shell=True,
    )
    prepared_files["duplicate"] = target_excutable
    log_success(
        f"Patch {os.path.basename(target_files[BaseFile.EXECUTABLE])} to {os.path.basename(target_excutable)} successfully."
    )
    #! Add: patch ohter sharedlib such as libpthread
    # debug symbol and source
    prepared_files[BaseFile.DBG] = (
        glibc_files[BaseFile.DBG] if os.path.exists(glibc_files[BaseFile.DBG]) else None
    )
    prepared_files[BaseFile.SRC] = (
        glibc_files[BaseFile.SRC] if os.path.exists(glibc_files[BaseFile.SRC]) else None
    )
    return prepared_files


def do_generate(args: dict):
    from jinja2 import Template

    template = Template(open(os.path.expanduser(config["template"])).read())
    rendered_template = template.render(
    filename=os.path.basename(args["target"]),
    libcname=args.get("libc_path"),
    host=args.get("host"),
    port=args.get("port"),
    debug_file_directory=args.get("dbg_path"),
    source_dircetory=args.get("src_path"),
    author=args.get("author"),
    time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )
    if os.path.exists(config["script_name"]):
        if not prompt("Script exists, do you want to cover it?"):
            log_info("Haven't cover it. No script genarated.")
            exit(0)
    with open(config["script_name"], "w") as f:
        f.write(rendered_template)
    subprocess.run(f"chmod +x \"{config['script_name']}\"", text=True, shell=True)
    click.echo(f"Generate script {config['script_name']} successfully.")


def do_get_vmlinux(bz: str):
    log_info("Start generating vmlinux.")
    vmlinux = os.path.join(os.path.dirname(bz), "exploit/vmlinux")
    if not os.path.exists(vmlinux):
        subprocess.run(
            f"vmlinux-to-elf {bz} {vmlinux}",
            text=True,
            shell=True,
        )
        log_info("Successfully!")
    else:
        log_info("Exists, skipping.")
    return vmlinux


def do_extract_cpio(exploit_dir: str, cpio: str):
    log_info("Start extract cpio.")
    extract_path = os.path.join(os.path.dirname(cpio), "exploit/extracted")
    if not os.path.exists(extract_path):
        os.mkdir(extract_path)
        subprocess.run(
            f"cd {extract_path}; cpio -i --no-absolute-filenames -F {cpio}",
            text=True,
            shell=True,
        )
        log_info("Successfully!")
    else:
        log_info("Exists, skipping.")
    log_info("Walk for kpm files")
    ko_files_list = []
    for root, dirs, files in os.walk(extract_path):
        for file in files:
            if file.endswith(".ko"):
                ko_file_path = os.path.join(root, file)
                ko_files_list.append(ko_file_path)
                shutil.copy(
                    ko_file_path,
                    os.path.join(exploit_dir, os.path.basename(ko_file_path)),
                )
    log_success(f"Found {len(ko_files_list)} {' '.join(ko_files_list)}")
    return extract_path, ko_files_list


def do_generate_debug(script: str, cpio: str):
    log_info("Start generate debug script.")
    with open(script, "r") as f:
        content = f.read()
    # complie exp
    compiler_script = os.path.join(config["kernel_file_path"], "compiler.sh")
    with open(compiler_script, "r") as f:
        content = f.read() + "\n" + content
    content.replace("rootfs.cpio", os.path.basename(cpio))
    run_script = os.path.join(os.path.dirname(script), "exploit/run.sh")
    if not os.path.exists(run_script):
        with open(run_script, "w") as f:
            f.write(content)
        subprocess.run(f"chmod +x {run_script}", text=True, shell=True)
        log_info("Create run.sh!")
    debug_script = os.path.join(os.path.dirname(script), "exploit/debug.sh")
    if not os.path.exists(debug_script):
        # nokaslr
        if "nokaslr" in content and "kaslr" not in content:
            content.replace("kaslr", "nokaslr")
        # gdb on :1234
        if "-s " not in content and "-gdb" not in content:
            lines = content.split("\\")
            content = "\\".join(
                lines[:-1] + [lines[-1].rstrip(" \n") + " \\\n\t-s -S\n"]
            )
        # write to debug_script
        with open(debug_script, "w") as f:
            f.write(content)
        subprocess.run(f"chmod +x {debug_script}", text=True, shell=True)
        log_info("Create debug.sh!")
    log_info("Finish.")
    return debug_script

    # def do_get_kpm_addr(script, kpm):
    # from pwn import *
    # os.chdir(os.dirname(script))
    # p = process(script)
    # p.recvuntil()


def do_generate_gdbscript(vmlinux, extracted_dir, kpm):
    # src_gdbscript = os.path.join(config['kernel_file_path'], ".gdbinit")
    log_info("Start generate gdbscript at exploit/.gdbinit.")
    gdbscript_path = os.path.join(os.path.dirname(vmlinux), ".gdbinit")
    if not os.path.exists(gdbscript_path):
        content = f"target remote :1234\nfile vmlinux\nadd-symbol-file {os.path.join('./extracted', os.path.basename(kpm))}"
        with open(gdbscript_path, "w") as f:
            f.write(content)
        log_info("Successfully!")


def do_generate_exp(exploit_dir: str):
    log_info("Start generate exploit script.")
    exp_path = os.path.join(exploit_dir, "exp.c")
    if not os.path.exists(exp_path):
        shutil.copy(os.path.join(config["kernel_file_path"], "exp.c"), exp_path)
        log_info("Successfully!")


# command wrapper functions


def precmd(ctx):
    global config
    with open(ctx.params["config"], "r") as file:
        config = json.load(file)
        config["file_path"] = os.path.expanduser(config["file_path"])
        config["threads"] = ctx.params["threads"]
        config["force"] = ctx.params["force"]
        config["kernel_file_path"] = os.path.expanduser(config["kernel_file_path"])


@click.group(invoke_without_command=False)
@click.pass_context
@click.option("--verbose", is_flag=True)
@click.option(
    "--config",
    default=os.path.expanduser("~/.config/cpwn/config.json"),
    type=click.Path(exists=True, dir_okay=False, readable=True),
)
@click.option("--force", is_flag=True, help="Download anyway.", default=False)
@click.option("--threads", help="Threads for download and extract")
def cli(ctx, verbose, config, threads, force):
    if ctx.invoked_subcommand is not None:
        precmd(ctx)


@cli.command(help="Initialize pwn game exploit enviroment.")
@click.option("--host", help="Remote host.", default="127.0.0.1")
@click.option("--port", help="Remote port.", default="1337")
@click.option("--nopatch", help="Just generate exp without patching elf.", is_flag=True, default=False)
@click.option("--noexp", help="Just patch elf without generating exp.", is_flag=True, default=False)
def init(host, port, nopatch:bool, noexp:bool):
    target_files = detect()
    template_args = {}
    prepared_files = {}
    template_args["target"] = target_files[BaseFile.EXECUTABLE]
    if not nopatch:
        prepared_files = do_patch(target_files)
        template_args["dbg_path"] = prepared_files.get(BaseFile.DBG)
        template_args["src_path"] = prepared_files.get(BaseFile.SRC)
        template_args["libc_path"] = prepared_files.get(BaseFile.LIBC)
    # generate exp
    if not noexp:
        template_args["host"] = host
        template_args["port"] = port
        template_args["author"] = config.get("author")
        do_generate(template_args)
    

@cli.command(help="Fetch the popular version.")
def fetch():
    base_url = "https://launchpad.net"
    version_url = base_url + "/ubuntu/+source/glibc"
    soup = BeautifulSoup(requests.get(version_url).text, "lxml")
    rows = soup.find_all("tr", class_="archive_package_row")
    download_list = []
    for row in tqdm(rows, desc="Fetching versions", leave=False, ascii=True):
        version = row.find_all("a")[1].get_text().strip()
        for expect_arch in config["archs"]:
            download_list += generate_expect_download_list(version, expect_arch)
    log_success(f"Get {len(rows)} verions, start downloading.")
    multi_download(download_list)


@cli.command(help="Initialize kernel exploit enviroment.")
@click.argument(
    "script",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    # help="Path of qemu start script.",
)
@click.argument(
    "cpio",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    # help="Path of cpio archive.",
)
@click.argument(
    "bz",
    type=click.Path(exists=True, file_okay=True, dir_okay=False),
    # help="Path of boot executable bzImage.",
)
# @click.argument(
# "kpm",
# type=click.Path(exists=True, file_okay=True, dir_okay=False),
# help="Path of kernel module.",
# )
def kernel(script, cpio, bz):
    # print(f"ok {script}, {cpio}, {bz}, {kpm}")
    # auto find addr (start qemu), generate debug script.
    # here just copy directory
    pwd = os.getcwd()
    script = os.path.join(pwd, os.path.basename(script))
    exploit_dir = os.path.join(pwd, "exploit")
    if not os.path.exists(exploit_dir):
        os.mkdir(exploit_dir)
    cpio = os.path.join(pwd, os.path.basename(cpio))
    bz = os.path.join(pwd, os.path.basename(bz))
    vmlinux = do_get_vmlinux(bz)
    extracted_dir, kpm_list = do_extract_cpio(exploit_dir, cpio)
    gdbscript = do_generate_gdbscript(vmlinux, extracted_dir, kpm_list[0])
    debug_script = do_generate_debug(script, cpio)
    exp = do_generate_exp(exploit_dir)
    # shutil.copytree(config["kernel_file_path"], os.path.join(os.getcwd(), "exploit"))


if __name__ == "__main__":
    cli()
