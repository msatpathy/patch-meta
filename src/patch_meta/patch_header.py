#!/usr/bin/env python3

#!/usr/bin/env python3

# Copyright (c) 2026 Milan Satpathy
# SPDX-License-Identifier: MIT
#
# Description: Add metadata and signatures to backported patches.
#
# Author: Milan Satpathy

import subprocess
import logging as log
from pathlib import Path
import configparser
from requests import get
import argparse
from urllib.parse import urlparse
from urllib.request import urlopen
from urllib.error import URLError
import re
import os

CONFIG_FILE = "~/.mv-patch-header/config.ini"

class PatchHeader:

    def __init__(self, cve_id: str, backport_url: str, file_path: str, import_from: str = ""):
        self.identity = UserIdentity()
        self.cve_id = cve_id
        self.backport_url = backport_url
        self.file_path = file_path

    def _fetch_user_identity(self):
        self.identity.initialize()

    def _split_patch_content(self, lines: list[str]):
        boundary = None
        for index, line in enumerate(lines): 
            if line.rstrip() == "---":
                boundary = index
            elif "diff --git" in line:
                break
         
        if boundary is None:
            raise ValueError("Could not find valid header separator. Check patch format")

        return { "commit_message": lines[:boundary], "patch": lines[boundary:]}


    def create_patch_header(self):
        
        self._fetch_user_identity()

        response = get(self.backport_url)
        response.raise_for_status()

        #lines = [l.decode() for l in response.iter_lines()]
        lines = response.text.splitlines(keepends=True)
        extract_upstream_patch = self._split_patch_content(lines)
        comment = "".join(extract_upstream_patch["commit_message"])

        header = f"{comment}\n"
        header += f"Upstream-Status: Backport from [ {self.backport_url} ]\n"
        header += f"CVE: {self.cve_id}\n"
        header += f"Signed-off-by: {self.identity.username} <{self.identity.email}>\n"

        return header

    def write_patch_header(self, header: str, confirm: bool):
        
        if confirm:
            os.system("clear")
            print("="*80)
            print(header)
            print("="*80)
            answer = input("\nWrite this header to the patch? [Y/n]: ").strip().lower()
            if not answer in ("", "y", "yes"):
               raise PatchError("Patch header update cancelled")

        with open(self.file_path, "r") as f:
            lines = f.readlines()
        
        extract_backport_patch = self._split_patch_content(lines)
        patch_body = "".join(extract_backport_patch["patch"])
        new_patch = header + patch_body
      
        with open(self.file_path, "w") as f:
            f.write(new_patch)

class UserIdentity:

    def __init__(self, name :str = "", email :str = ""):
      self.username = name
      self.email = email

    def initialize(self):
        self.username = self._get_user_name()
        self.email = self._get_user_email()

    def _get_user_email(self):

        try:
            response = subprocess.run(['git', 'config', 'user.email'], check = True, capture_output=True, text=True)
            return response.stdout.strip()

        except(subprocess.CalledProcessError):
          log.warning("Git user.email not set!!")

        c = Config()
        log.info(f"Trying to fetch from config file: {c.configfile}")
        e = c.get("user", "email")
        if e:
            return e
          
        else:
            raise ValueError("Email not found. Set email and try again.")

    def _get_user_name(self):

        try:
            response = subprocess.run(['git', 'config', 'user.name'], check = True, capture_output=True, text=True)
            return response.stdout.strip()

        except(subprocess.CalledProcessError):
          log.warning("Git user.name not set!!")
          
        c = Config()
        log.info(f"Trying to fetch from config file: {c.configfile}")
        n = c.get("user", "name")
        if n:
            return n

        else:
            raise ValueError("Username not found. Set username and try again.")

class Config:

    def __init__(self, cfile : str = CONFIG_FILE):

        self.configparser = configparser.ConfigParser()
        self.configfile = Path(cfile).expanduser()

        self._load_configfile()
    
    def _load_configfile(self):

        if self.configfile.exists():
            self.configparser.read(self.configfile)

    def _create_configfile(self):

        config_dir = self.configfile.parent
        
        try:
            config_dir.mkdir(mode=0o755, parents=True, exist_ok = True)
            self.configfile.touch(mode=0o644, exist_ok = True)
        
        except OSError as e:
            log.error(f"Failed to create config file {self.configfile}: {e}")

    def _update_configfile(self):

        try:
            if not self.configfile.exists():
                self._create_configfile()

            with self.configfile.open("w") as f:
                self.configparser.write(f)

        except OSError as e:
            log.error(f"Failed to write config file {self.configfile}: {e}")

    def get(self, section: str, key: str):

       self._load_configfile()
       value = self.configparser.get(section, key, fallback=None)
       return value
   
    def set(self, section: str, key: str, val : str):

        if not self.configparser.has_section(section):
            self.configparser.add_section(section)

        self.configparser.set(section, key, val)

        self._update_configfile()




def cve_parser(cve: str = ""):
    if not cve:
      cve = input("\nEnter CVE: ").strip()

    cve = cve.upper()

    if not re.fullmatch(r"CVE-20\d{2}-\d+", cve):
        raise ValueError("Invalid CVE number format")

    return cve

def patch_finder():
    pattern = re.compile(r"00\d{2}-.*\.patch")

    files = [ f for f in Path(".").iterdir() if f.is_file() and pattern.fullmatch(f.name) ]

    file_list = [(n,str(file)) for n,file in enumerate(files)]
    print("\n")
    for record in file_list:
        print(f"[ {record[0] } ] {record[1]}")
    print("\n")
    return file_list 

def patch_rename(file: str, cve: str = ""):
    _filename = Path(file).name
    _filepath = Path(file).parent
    if re.fullmatch(r"CVE-\d{4}-\d+\.patch", _filename):
        return
    suggested = f"{cve.upper()}.patch" if cve else ""
    if suggested:
        answer = input(
            f"\nPatch filename: {_filename}\n"
            f"Suggested filename: {suggested}\n"
            f"Rename? [Y/n/custom name]: "
        ).strip()

        if not answer or answer.lower() == "y":
            rename = suggested
        elif answer.lower() == "n":
            return
        else:
            rename = answer


    new_file_path = _filepath.joinpath(rename)
    Path(file).rename(new_file_path)


def file_path_parser(filepath: str = ""):

    if not filepath:
        suggestions = patch_finder()
        patch_file = input(f"Enter patch file (or choose a number from the list)\n: ").strip()
    
        if patch_file.isdigit() and int(patch_file) < len(suggestions):
            filepath = suggestions[int(patch_file)][1]
        elif patch_file:
            filepath = patch_file
        else:
            raise ValueError("Invalid or empty file path")
        
    if not Path(filepath).exists():
        raise FileNotFoundError(f"No such file found:{filepath}")
    if not filepath.endswith(".patch"):
        log.warning(f"A patch file name should end with .patch")

    return filepath

def normalize_github_url(url: str) -> str:
    url = url.strip()

    if "github.com" in url and not url.endswith(".patch"):
        url += ".patch"

    return url

def url_parser(url: str = ""):
    
    if not url:
        url = input("\nEnter backport from (url): ").strip()

    result = urlparse(url)

    if result.scheme not in ("http", "https") or not bool(result.netloc):
        raise ValueError("Invalid url")
        
    url = normalize_github_url(url)

    try:
        with urlopen(url, timeout=5):
            pass
    except URLError:
            raise ConnectionError(f"Unable to connect to: {url}")

    return url
