#!/bin/python3
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

def download_one(file):
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
                dynamic_ncols=True,
                colour="yellow",
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
      


def precmd(ctx):
    global config
    with open(ctx.params["config"], 'r') as file:
        config = json.load(file)
        config['file_path'] = os.path.expanduser(config['file_path'])


@click.group(invoke_without_command=False)
@click.pass_context
@click.option('--verbose', is_flag=True)
@click.option('--config', default=os.path.expanduser("~/.config/cpwn/config.json"), type=click.Path(exists=True, dir_okay=False, readable=True))
def cli(ctx, verbose, config):
    if ctx.invoked_subcommand is not None:
        precmd(ctx)


def detect() -> dict:
    target_files = {}
    pwd = os.getcwd()
    mime = magic.Magic(mime = True)
    for file in os.listdir(pwd):
        file_path = os.path.join(pwd, file)
        if os.path.isdir(file_path):
            continue
        file_type = mime.from_file(file_path)
        if (file_type == "application/x-pie-executable" or file_type == 'application/x-executable') and "_patched" not in file:
            target_files["executable"] = file_path
            click.echo(f"Detect excutable file {file}")
        if file_type == "application/x-sharedlib":
            if "libc" in file_path:
                target_files["libc.so.6"] = file_path
                click.echo(f"Detect libc.so.6 file {file}")
            elif "ld" in file_path:
                target_files["ld"] = file_path
                click.echo(f"Detect ld file {file}")
            else:
                target_files[os.path.basename(file_path)] = file_path
                click.echo(f"Detect ohter shared lib {file}")
    return target_files


def get_version(file):
    result = subprocess.run(f"strings {file} | grep GLIBC | tail -n 1", stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
    return result.stdout.split("(Ubuntu GLIBC ")[1].split(')')[0]


def patch():
    pass


# @cli.command()
def choose():
    table = PrettyTable(['Idx','Version'])
    table.hrules = True
    lib_path = os.path.join(config['file_path'])
    libc_list = []
    for dir in os.listdir(lib_path):
        libc_list.append(dir)
    libc_list = sorted(libc_list, key = lambda x: x)
    for i, row in enumerate(libc_list):
        table.add_row([str(i), row])
    print(table)
    idx = int(input('Choose the version you wnat to modify:'))
    return libc_list[idx]


@cli.command()
@click.option("--debug", is_flag=True, help="With symbol debug info.", default=True)
@click.option("--src", is_flag=True, help="With libc source.", default=True)
@click.option("--host", help="Remote host.", default="127.0.0.1")
@click.option("--port", help="Remote port.", default="1337")
def init(debug, src, host, port):
    target_files = detect()
    # copy patched
    if "executable" not in target_files:
        click.echo("No excutable! Make sure your pwn file without postfix '_patched'")
        exit(-1)
    executable_path = target_files['executable']
    executable_copy = executable_path + '_patched'
    if os.path.exists(executable_copy):
        if input("Patch executable exists, do you want to cover it?(y/n)") == 'n':
            click.echo("Exit.")
            exit(0)
    shutil.copy(executable_path, executable_copy)
    subprocess.run(f"chmod +x {executable_copy}", text=True, shell=True)
    subprocess.run(f"chmod +x {executable_path}", text=True, shell=True)

    # find libc
    arch = ELF(executable_copy).arch
    if "libc.so.6" not in target_files:
        print("No libc file find in your workdir.")
        if input("Do you want to list the table of versions in your enviroment?(y/n)") == 'n':
            exit(0)
        version = choose()
    else:
        version = get_version(target_files['libc.so.6'])
    expect_dir = os.path.join(config['file_path'], version)
    libc_path = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/libc.so.6")
    if not os.path.exists(libc_path):
        click.echo("This version of libc doesn't exist!")
        exit(0)
        # download_one()
    subprocess.run(f"patchelf --replace-needed libc.so.6 {libc_path} {executable_copy}", text=True, shell=True)
    ld_path = os.path.join(expect_dir, f"libc6_{version}_{arch}/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2")
    if not os.path.exists(ld_path):
        click.echo("This version of ld doesn't exist!")
        exit(-2)
    subprocess.run(f"patchelf --set-interpreter {ld_path} {executable_copy}", text=True, shell=True)
    # for others sharedlib
        # for k, v in enumerate(target_files):
        #     pass
    
    # generate exp
    from jinja2 import Template
    template = Template(open(os.path.expanduser(config['template'])).read())
    dbg_path = os.path.join(expect_dir, f"libc6-dbg_{version}_{arch}/usr/lib/debug")
    if not os.path.exists(dbg_path) and not debug:
        dbg_path = None
    src_path = os.path.join(expect_dir, f"glibc-source_{version}_all/usr/src/glibc/glibc-2.35")
    if not os.path.exists(src_path) and not src:
        src_path = None
    rendered_template = template.render(
        filename=os.path.basename(executable_copy),
        libcname=libc_path,
        host=host,
        port=port,
        debug_file_directory=dbg_path,
        source_dircetory=src_path,
        author=config['author'],
        time=datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    )
    if os.path.exists(config['script_name']):
        if input("Script exists, do you want to cover it?(y/n)") == 'n':
            click.echo("Don't cover.")
            click.echo(rendered_template)
    else:
        with open(config['script_name'], 'w') as f:
            f.write(rendered_template)
        click.echo(f"Generate script {config['script_name']} successfully.")


@cli.command()
@click.option("--force", is_flag=True, help="Download anyway.")
def fetch(force):
    from bs4 import BeautifulSoup
    base_url = "https://launchpad.net"
    version_url = base_url + "/ubuntu/+source/glibc"
    click.echo(click.style(f"Start fetching versions.", fg='blue'))
    soup = BeautifulSoup(requests.get(version_url).text, 'lxml')
    rows = soup.find_all('tr', class_='archive_package_row')
    version_list = []
    download_list = []
    for row in tqdm(rows, desc="Fetching versions", leave=False, dynamic_ncols=True):
        name = row.find_all('a')[1].get_text().strip()
        url = base_url + row.find_all('a', class_='expander')[0]["href"].strip()
        store_path = os.path.join(config['file_path'], name)
        exists = os.path.exists(store_path)
        files = {}
        if not exists or force:
            try:
                os.makedirs(store_path)
            except:
                pass
            expect_pkg = [
                f'{pkg}_{name}_{arch}.deb' if  pkg != 'glibc-source' else f'{pkg}_{name}_all.deb'
                for pkg in config['pkgs'] for arch in config['archs']
                ]
            cpkgs = BeautifulSoup(requests.get(url).text, 'lxml').find_all('li', class_='package binary')
            for cpkg in cpkgs:
                cpkg_name = cpkg.find_all('a')[0].get_text().strip()
                cpkg_url = cpkg.find_all('a')[0]['href']
                if cpkg_name in expect_pkg:
                    files[cpkg_name] = cpkg_url
                    download_list.append((cpkg_url, os.path.join(store_path, cpkg_name)))
        elif not force:
            click.echo(click.style(f"Version {name} exists, skip.", fg='blue'))
        version_list.append((name, url, exists, files))
    click.echo(click.style(f"Get {len(version_list)} verions, start downloading.", fg='blue'))
    from concurrent.futures import ThreadPoolExecutor, as_completed
    cnt = 0
    with ThreadPoolExecutor(max_workers=config['threads']) as executor:
        future_to_file = {executor.submit(download_one, file): file for file in download_list}
        for future in tqdm(iterable=as_completed(future_to_file),
                           desc="All to download",
                           total=len(download_list),
                           dynamic_ncols=True,
                           colour="green",
                           leave=False,
                           ):
            file = future_to_file[future]
            try:
                download_list.remove(file)
                cnt += 1
            except Exception as exc:
                click.echo(click.style(f"Fetch {os.path.basename(file[1])} generated an exception: {exc}", fg='red'))
    click.echo(click.style(f"Successfully download {cnt} files.", fg='blue'))
    if len(download_list) != 0:
        click.echo(f"These download or extract failed: {download_list}")


if __name__ == '__main__':
    cli()