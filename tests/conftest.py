"""
Software Name : decret (DEbian Cve REproducer Tool)
Version : 0.1
SPDX-FileCopyrightText : Copyright (c) 2023-2025 Orange
SPDX-License-Identifier : BSD-3-Clause

This software is distributed under the BSD 3-Clause "New" or "Revised" License,
the text of which is available at https://opensource.org/licenses/BSD-3-Clause
or see the "license.txt" file for more not details.

Authors : Clément PARSSEGNY, Olivier LEVILLAIN, Maxime BELAIR, Mathieu BACOU,
Nicolas DEJON
Software description : A tool to reproduce vulnerability affecting Debian
It gathers details from the Debian metadata and exploits from exploit-db.com
in order to build and run a vulnerable Docker container to test and
illustrate security concepts.
"""

from argparse import Namespace
import os
import sys
import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# pylint:disable=wrong-import-position
from decret.decret import (
    argparse,
    choose_one,
    collapse_list,
    convert_tables,
    CVENotFound,
    filter_tables,
    get_cve_tables,
    get_snapshots,
    versions_lookup,
)


@pytest.fixture
def bullseye_args():
    return Namespace(
        release="bullseye",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
        vulnerable_version=None,
    )


@pytest.fixture
def wheezy_args():
    return Namespace(
        release="wheezy",
        fixed_version=None,
        cache_main_json_file=None,
        bin_package=None,
        vulnerable_version=None,
    )


@pytest.fixture
def cve_numbers():
    file_path = "tests/test-material/cves.txt"
    with open(file_path, "r", encoding="utf8") as file:
        return [line.strip() for line in file if line.strip()]


@pytest.fixture
def found_tables(cve_numbers):
    results = {}
    errored_on_search = []

    for cve_number in cve_numbers:
        args = argparse.Namespace()
        args.bin_package = None
        args.method = None
        args.cve_number = cve_number
        args.release = None

        try:
            info_table, fixed_table = get_cve_tables(args)
            results[cve_number] = (info_table, fixed_table)
        except CVENotFound as e:
            errored_on_search.append((cve_number, e))
            continue
    return results


@pytest.fixture
def filtered_tables(found_tables):
    results = {}
    args = argparse.Namespace()
    args.bin_package = None
    args.method = None
    args.release = False
    for cve, (info_table, fixed_table) in found_tables.items():
        info_table, fixed_table = filter_tables(info_table, fixed_table)
        results[cve] = (info_table, fixed_table)
    return results


@pytest.fixture
def converted_tables(filtered_tables):
    results = {}
    for cve, (info_table, fixed_table) in filtered_tables.items():
        cve_list = convert_tables(info_table, fixed_table)
        results[cve] = cve_list
    return results


@pytest.fixture
def vuln_configs(converted_tables):
    for cve_number, cve_list in converted_tables.items():
        args = argparse.Namespace()
        args.bin_package = None
        args.method = None
        args.cve_number = cve_number

        versions_lookup(cve_list, args)

    return converted_tables


@pytest.fixture
def timestamps(vuln_configs):
    for cve_number, cve_list in vuln_configs.items():
        args = argparse.Namespace()
        args.bin_package = None
        args.method = None
        args.cve_number = cve_number
        get_snapshots(cve_list, args)
    return vuln_configs


@pytest.fixture
def collapsed_lists(timestamps):
    results = {}
    for cve_number, cve_list in timestamps.items():
        args = argparse.Namespace()
        args.bin_package = None
        args.method = None
        args.bin_package = None
        args.release = None
        cve_list = collapse_list(cve_list, args)
        results[cve_number] = cve_list

    return results


@pytest.fixture
def chosen_configs(collapsed_lists):
    results = {}
    for cve_number, cve_list in collapsed_lists.items():
        choice = choose_one(cve_list)
        results[cve_number] = choice

    return results
