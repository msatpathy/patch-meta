#!/usr/bin/env python3

# Copyright (c) 2026 Milan Satpathy
# SPDX-License-Identifier: MIT
#
# Description: Add metadata and signatures to backported patches.
#
# Author: Milan Satpathy



import argparse
import sys
import logging as log

from .patch_header import (
    PatchHeader,
    cve_parser,
    file_path_parser,
    patch_rename,
    url_parser,
)


def parse_args():

    parser = argparse.ArgumentParser(
            description="Add header and signature to backported patch"
            )

    parser.add_argument(
            "-u", "--url",
            help="Upstream commit URL",
            )

    parser.add_argument(
            "-f", "--file",
            help="file name of the patch to be modified.Add path if not in current directory"
            )

    parser.add_argument(
            "-c","--cve",
            help="add CVE id.Both CAPS/small case works"
            )

    return parser.parse_args()

def main():
    
    args = parse_args()
    
    try:
        backport_url = url_parser(args.url)
        file_path = file_path_parser(args.file)
        cve_id = cve_parser(args.cve)

        patch_header = PatchHeader(
            cve_id = cve_id,
            backport_url = backport_url,
            file_path = file_path,
        )

        header = patch_header.create_patch_header()
        patch_header.write_patch_header(header, confirm = True)
        patch_rename(file=file_path, cve=cve_id)
    
    except Exception as e:
        log.error("%s", e)
        return 1


if __name__ == "__main__":
    main()
