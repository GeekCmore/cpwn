#!/bin/python3
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
    log_base(msg, 'blue')


def log_success(msg):
    log_base(msg, 'green')


def log_error(msg):
    log_base(msg, 'red')
    exit(-1)


def prompt(msg:str):
    tmp = input(msg+" (N/n to refuse, others to argee): ")
    return tmp != 'n' and tmp != 'N'


def download_and_extract(file):
    try:
        url = file[0]
        deb_filename = file[1]
        extract_path = ".".join(deb_filename.split('.')[:-1])
        tmp_file = deb_filename + '.download'
        if not os.path.exists(deb_filename):
            resp = requests.get(url, stream=True)
            total = int(resp.headers.get('content-length', 0))
            with open(tmp_file, 'wb') as file, tqdm(
                desc=os.path.basename(deb_filename),
                total=total,
                unit='iB',
                unit_scale=True,
                unit_divisor=1024,
                ascii=True,
                leave=False,
            ) as bar:
                for data in resp.iter_content(chunk_size=1024):
                    size = file.write(data)
                    bar.update(size)
            subprocess.run(['mv', tmp_file, deb_filename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if not os.path.exists(extract_path):
                subprocess.run(['dpkg', '-x', deb_filename, extract_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                subprocess.run(f"chmod -R +x {extract_path}", text=True, shell=True)

        if "glibc-source" in extract_path:
            source_path = os.path.join(extract_path, "usr/src/glibc/")
            version_name = extract_path.split('glibc-source_')[1][:4]
            subprocess.run(['tar', '-xvf', os.path.join(source_path, f"glibc-{version_name}.tar.xz"), '-C', source_path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return "Successfully!"
    except Exception as e:
        subprocess.run(['rm', '-f', tmp_file], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        subprocess.run(['rm', '-f', deb_filename], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        return f"Error: {e}"


def download_give_version_arch(version, arch):
    download_list = generate_expect_download_list(version, arch)
    multi_download(download_list)


def multi_download(download_list):
    from concurrent.futures import ThreadPoolExecutor, as_completed
    cnt = 0
    with ThreadPoolExecutor(max_workers=config['threads']) as executor:
        future_to_file = {executor.submit(download_and_extract, file): file for file in download_list}
        for future in tqdm(iterable=as_completed(future_to_file),
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
                log_error(click.style(f"Fetch {os.path.basename(file[1])} generated an exception: {exc}", fg='red'))
    log_success(click.style(f"Successfully download {cnt} files.", fg='blue'))
    if len(download_list) != 0:
        log_error(f"These download or extract failed: {download_list}")


def fetch_archs_by_version(version:str) -> dict:
    '''
        use the given version of glibc to fetch arch id
        such as https://launchpad.net/ubuntu/+source/glibc/2.35-0ubuntu3.7
    '''
    base_url = 'https://launchpad.net'
    url = base_url + "/ubuntu/+source/glibc/" + version
    div = BeautifulSoup(requests.get(url).text, 'lxml').find_all('div', {'id': 'source-builds'})[0]
    arch_idx = {}
    for a in div.find_all('a')[1:]:
        arch_idx[a.get_text()] = a['href'] if 'http' in a['href'] else base_url + a['href']
    return arch_idx


def fetch_remote_files(url):
    '''
        fetch all files by build id
        such as https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/28112201
    '''
    built_files = {}
    # built_files_url = "https://launchpad.net/~ubuntu-security/+archive/ubuntu/ppa/+build/" + id
    soup = BeautifulSoup(requests.get(url).text, 'lxml')
    cpkgs = soup.find_all('div', {'id': 'files', 'class': 'portlet'})[0].find_all('a', {'class': 'sprite download'})
    for cpkg in cpkgs:
        cpkg_name = cpkg.get_text().strip()
        cpkg_url = cpkg['href']
        built_files[cpkg_name] = cpkg_url
    return built_files


def generate_expect_download_list(version, arch) -> list:
    expect_pkgs = []
    for expect_pkg in config['pkgs']:
        if expect_pkg == 'glibc-source':
            if arch == 'amd64':         # only amd64 has glibc-source_xxxxxx_all.deb
                expect_pkgs.append(f'{expect_pkg}_{version}_all.deb')
        else:
            expect_pkgs.append(f'{expect_pkg}_{version}_{arch}.deb')
    arch_urls = fetch_archs_by_version(version)
    remote_files_map = fetch_remote_files(arch_urls[arch])
    arch_store_path = dir_from_version_arch(version, arch)
    download_list = []
    for expect_file in expect_pkgs:
        expect_file_path = os.path.join(arch_store_path, expect_file)
        download_list.append((remote_files_map[expect_file], expect_file_path))
    return download_list


def dir_from_version_arch(version, arch):
    store_path = os.path.join(config['file_path'], version)
    arch_path = os.path.join(store_path, arch)
    if not os.path.exists(arch_path):
        os.makedirs(arch_path)
    return arch_path

def detect(target_files:dict = {}) -> dict:
    '''
        Detect current workdir to determine target files.
    '''
    pwd = os.getcwd()
    mime = magic.Magic(mime = True)
    for k, v in target_files.items():
        log_info(f"You choose {v} as your {k} file, skip detecting it.")
    
    for filename in os.listdir(pwd):
        file_path = os.path.join(pwd, filename)
        if os.path.isdir(file_path):
            continue
        file_type = mime.from_file(file_path)
        if file_type == "application/x-pie-executable" or file_type == 'application/x-executable':
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
    result = subprocess.run(f"strings {file} | grep GLIBC | tail -n 1", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.split("(Ubuntu GLIBC ")[1].split(')')[0]


def get_glibc_files(version:str, arch:str) -> dict:
    '''
        get version directory by glibc version and executable arch.
    '''
    glibc_files = {}
    expect_dir = os.path.join(config['file_path'], version)
    glibc_files[BaseFile.LIBC] = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/libc.so.6")
    glibc_files[BaseFile.LD] = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    glibc_files[BaseFile.DBG] = os.path.join(expect_dir, f"libc6-dbg_{version}_{arch}/usr/lib/debug")
    glibc_files[BaseFile.SRC] = os.path.join(expect_dir, f"glibc-source_{version}_all/usr/src/glibc/glibc-2.35")
    # for k, v in glibc_files.items():
    #     if not os.path.exists(v):
    #         del glibc_files[k]
    return glibc_files


def choose_version():
    table = PrettyTable(['Idx','Version'])
    table.hrules = True
    lib_path = os.path.join(config['file_path'])
    libc_list = []
    for dir in os.listdir(lib_path):
        libc_list.append(dir)
    libc_list = sorted(libc_list, key = lambda x: x)
    for i, row in enumerate(libc_list):
        table.add_row([str(i), row])
    log_info(table)
    idx = int(input('Choose the version you wnat to modify:'))
    return libc_list[idx]


def copy(filename:str, filecopy:str) -> str:
    if not os.path.exists(filename):
        click.echo(f"[-] Error: {filename} dosen't exists!")
    elif os.path.exists(filecopy):
        prompt(f"The duplicate {filecopy} exists. Do you want to cover it?")
    else:
        shutil.copy(filename, filecopy)


# command handle functions

def do_patch(target_files):
    '''
        Patch the target executable file, and search for 
    '''
    # precheck
    prepared_files = {}
    target_excutable = target_files[BaseFile.EXECUTABLE] + '_patched'  
    arch = ELF(target_files[BaseFile.EXECUTABLE]).arch
    version = get_version_by_libc(target_files[BaseFile.LIBC])
    glibc_files = get_glibc_files(version, arch)
    if BaseFile.LIBC not in glibc_files:
        log_info("No libc file find in your workdir.")
        if not prompt("Do you want to list the table of versions in your enviroment?"):
            exit(0)
        version = choose_version()
    expect_dir = os.path.join(os.path.join(config['file_path'], version), arch)
    libc_path = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/libc.so.6")
    ld_path = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    if not os.path.exists(libc_path) or not os.path.exists(ld_path):
        if prompt(f"You don't have {version} version of glibc, do you want to download?"):
            log_info("Start downloading...")
            download_give_version_arch(version, arch)
        else:
            log_error("No suitable glibc!")
        prepared_files[BaseFile.LIBC] = libc_path
    prepared_files[BaseFile.LIBC] = libc_path
    prepared_files[BaseFile.LD] = ld_path
    # copy and patch
    copy(target_files[BaseFile.EXECUTABLE], target_excutable)
    subprocess.run(f"chmod +x {target_excutable}", text=True, shell=True)
    subprocess.run(f"chmod +x {target_files[BaseFile.EXECUTABLE]}", text=True, shell=True)  
    subprocess.run(f"patchelf --replace-needed libc.so.6 {libc_path} {target_excutable}", text=True, shell=True)
    subprocess.run(f"patchelf --set-interpreter {ld_path} {target_excutable}", text=True, shell=True)
    prepared_files['duplicate'] = target_excutable
    log_success(f"Patch {os.path.basename(target_files[BaseFile.EXECUTABLE])} to {os.path.basename(target_excutable)} successfully.")
    #! Add: patch ohter sharedlib such as libpthread
    # debug symbol and 
    dbg_path = os.path.join(expect_dir, f"libc6-dbg_{version}_{arch}/usr/lib/debug")
    if os.path.exists(dbg_path): prepared_files[BaseFile.DBG] = dbg_path
    src_path = os.path.join(expect_dir, f"glibc-source_{version}_all/usr/src/glibc/glibc-{version[0:4]}")
    if os.path.exists(src_path): prepared_files[BaseFile.SRC] = src_path
    return prepared_files


def do_generate(args:dict):
    from jinja2 import Template
    template = Template(open(os.path.expanduser(config['template'])).read())
    rendered_template = template.render(
        filename=os.path.basename(args['target']),
        libcname=args['libc_path'],
        host=args['host'],
        port=args['port'],
        debug_file_directory=args['dbg_path'],
        source_dircetory=args['src_path'],
        author=args['author'],
        time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    if os.path.exists(config['script_name']):
        if not prompt("Script exists, do you want to cover it?"):
            log_info("Haven't cover it. No script genarated.")
            exit(0)
    with open(config['script_name'], 'w') as f:
        f.write(rendered_template)
    click.echo(f"Generate script {config['script_name']} successfully.")


# command wrapper functions
    
def precmd(ctx):
    global config
    with open(ctx.params["config"], 'r') as file:
        config = json.load(file)
        config['file_path'] = os.path.expanduser(config['file_path'])
        config['threads'] = ctx.params['threads']
        config['force'] = ctx.params['force']


@click.group(invoke_without_command=False)
@click.pass_context
@click.option('--verbose', is_flag=True)
@click.option('--config', default=os.path.expanduser("~/.config/cpwn/config.json"), type=click.Path(exists=True, dir_okay=False, readable=True))
@click.option("--force", is_flag=True, help="Download anyway.")
@click.option("--threads", help="Threads for download and extract")
def cli(ctx, verbose, config, threads, force):
    if ctx.invoked_subcommand is not None:
        precmd(ctx)


@cli.command()
@click.option("--host", help="Remote host.", default="127.0.0.1")
@click.option("--port", help="Remote port.", default="1337")
def init(host, port):
    target_files = detect()
    # get_files_by_version()
    prepared_files = do_patch(target_files)
    # generate exp
    template_args = {}
    template_args['dbg_path'] = prepared_files[BaseFile.DBG]
    template_args['src_path'] = prepared_files[BaseFile.SRC]
    template_args['libc_path'] = prepared_files[BaseFile.LIBC]
    template_args['host'] = host
    template_args['port'] = port
    template_args['target'] = prepared_files['duplicate']
    template_args['author'] = config['author']
    do_generate(template_args)


@cli.command(help="Fetch the popular version.")
def fetch():
    base_url = "https://launchpad.net"
    version_url = base_url + "/ubuntu/+source/glibc"
    soup = BeautifulSoup(requests.get(version_url).text, 'lxml')
    rows = soup.find_all('tr', class_='archive_package_row')
    download_list = []
    for row in tqdm(rows, desc="Fetching versions", leave=False, ascii=True):
        version = row.find_all('a')[1].get_text().strip()
        for expect_arch in config['archs']:
            download_list += generate_expect_download_list(version, expect_arch)
    log_success(f"Get {len(rows)} verions, start downloading.")
    multi_download(download_list)
 

if __name__ == '__main__':
    cli()