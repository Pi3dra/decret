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

import json
import os
import argparse
import re
from typing import Optional
from pathlib import Path
import sys
import requests
from bs4 import BeautifulSoup, Tag
from requests.exceptions import RequestException
from decret.config import (
    CACHE_PATH,
    DEFAULT_TIMEOUT,
    DEBIAN_RELEASES,
    LATEST_RELEASE,
    RUNS_ON_GITHUB_ACTIONS,
    FatalError,
    CVENotFound,
)

from decret.utils import (
    download_db,
    get_exploits,
    init_decret,
    write_cmdline,
    prepare_sources,
    write_dockerfile,
    build_docker,
    run_docker,
    version_distance,
    version_tuple,
)

METHOD_PRIORITY = {"Vulnerable": 4, "Bug": 3, "DSA": 2, "N-1": 1}

RELEASE_PRIORITY = {name: i for i, name in enumerate(DEBIAN_RELEASES)}
# For the time being as this is not stable
RELEASE_PRIORITY["sid"] = 0

DEBUG = False


class SearchError(BaseException):
    pass


def debug(string):
    if DEBUG:
        print(string)


def get_json(url):
    response = requests.get(url, timeout=DEFAULT_TIMEOUT)
    response.raise_for_status()
    response = response.json()["result"]
    return response


class VulnerableConfig:
    """
    This class holds all the necessary information to build a vulnerable container,
    It is used inside the CVE class to also know from which table entry it comes from,
    and the concerned Debian release.
    """

    # pylint: disable=too-many-arguments
    # pylint: disable=too-many-positional-arguments
    def __init__(self, version, method, timestamp=None, pkg_hash=None, bin_names=None):
        self.version = version
        self.method = method
        self.timestamp = timestamp
        self.pkg_hash = pkg_hash
        self.bin_names = bin_names

    def to_string(self):
        return (
            f"version: {self.version}\n   "
            f"timestamp: {self.timestamp}\n   "
            f"pkg_hash: {self.pkg_hash}\n   "
            f"bin_names: {self.bin_names}\n   "
            f"method: {self.method}  "
        )

    def to_dict(self):
        return {
            "version": self.version,
            "timestamp": self.timestamp,
            "method": self.method,
            "pkg_hash": self.pkg_hash,
            "bin_names": self.bin_names,
        }

    @classmethod
    def from_dict(cls, data):
        return cls(
            version=data.get("version"),
            timestamp=data.get("timestamp"),
            method=data.get("method"),
            pkg_hash=data.get("pkg_hash"),
            bin_names=data.get("bin_names"),
        )

    def get_bin_names(self, package):
        bin_names = []
        url = (
            f"http://snapshot.debian.org/mr/package"
            f"/{package}/{self.version}/binpackages"
        )

        try:
            response = get_json(url)
            for res in response:
                bin_names.append(res["name"])
        except requests.exceptions.RequestException as err:
            print(f"get_bin_names failed with: {err}")

    def get_hash_and_bin_names(self, args, package):
        try:
            url = f"http://snapshot.debian.org/mr/binary/{package}/{self.version}/binfiles"

            response = get_json(url)
            for res in response:
                if res["architecture"] == "amd64" or res["architecture"] == "all":
                    self.pkg_hash = res["hash"]
                    break
            self.bin_names = [package]

        except (requests.exceptions.RequestException, KeyError) as error:
            try:
                url = (
                    f"http://snapshot.debian.org/mr/package"
                    f"/{package}/{self.version}/srcfiles"
                )
                response = get_json(url)
                self.pkg_hash = response[-1]["hash"]
                self.get_bin_names(package)
            except Exception as error2:
                raise SearchError(
                    f"Couldn't find the source files for the linux package {package} with {error}."
                ) from error2

            if package == "linux":
                print("WARNING: Kernel Vulnerabilities are not yet supported by DECRET")
                self.bin_names = []

            # This might not work as intended with the new methods
            if args.bin_package:
                if args.bin_package in self.bin_names:
                    self.bin_names = [args.bin_package]
                else:
                    raise SearchError(
                        "Non existing binary package provided. Check your '-p' option."
                    ) from error

    def get_snapshot(self):
        try:
            url = f"http://snapshot.debian.org/mr/file/{self.pkg_hash}/info"
            response = get_json(url)
            self.timestamp = response[0]["first_seen"]
        except (requests.exceptions.RequestException, KeyError) as error:
            raise SearchError(f"failed to find snapshot with: {error}") from error


class Cve:
    """
    This class represents, for a single CVE,
    a single table entry from one of the two mid tables
    of this site (example on Heartbleed):
        https://security-tracker.debian.org/tracker/CVE-2014-0160
    The information is then aggregated and filtered to a list of Cve objects.
    """

    # pylint: disable=too-many-arguments
    # pylint: disable=too-many-positional-arguments
    def __init__(
        self,
        package,
        release,
        fixed=None,
        advisory=None,
        bugids=None,
        vulnerable=None,
    ):
        self.package = package
        self.release = release
        self.fixed = fixed
        self.vulnerable = vulnerable
        self.advisory = advisory
        self.bugids = bugids

    def to_string(self):
        vuln_version_strs = (
            "\n  " + "\n  ".join(x.to_string() for x in self.vulnerable)
            if self.vulnerable
            else "  None"
        )

        return (
            f"{self.package}:\n "
            f"release: {self.release}\n "
            f"fixed:\n  {self.fixed}\n "
            f"vulnerable:{vuln_version_strs}\n"
            f"advisory:\n  {self.advisory}\n "
            f"bugids:  {self.bugids} \n "
        )

    def to_dict(self):
        """Convert instance to dictionary."""
        assert self.vulnerable is not None

        return {
            "package": self.package,
            "release": self.release,
            "fixed": self.fixed,
            "advisory": self.advisory,
            "bugids": self.bugids,
            "vulnerable": [entry.to_dict() for entry in self.vulnerable],
        }

    @classmethod
    def from_dict(cls, data):
        """Create instance from dictionary."""
        return cls(
            package=data.get("package"),
            release=data.get("release"),
            fixed=data.get("fixed"),
            advisory=data.get("advisory"),
            bugids=data.get("bugids"),
            vulnerable=[
                VulnerableConfig.from_dict(entry) for entry in data.get("vulnerable")
            ],
        )

    def init_vulnerable(self):
        if self.vulnerable is None:
            self.vulnerable = []

    def preceding_version_lookup(self):
        self.init_vulnerable()
        if self.fixed is None or self.vulnerable is None:
            raise SearchError(
                f"package: {self.package} for {self.release} has no fixed_version"
            )

        url = f"http://snapshot.debian.org/mr/package/{self.package}/"

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            response = response.json()
        except RequestException as exc:
            raise SearchError(f"snapshot.debian.org request failed: {exc}") from exc
        except ValueError as exc:
            raise SearchError("Snapshot response is not valid JSON") from exc
        if "result" not in response or not isinstance(response["result"], list):
            raise SearchError(f"Unexpected payload shape: {response!r}")

        known_versions = [
            x["version"] for x in response["result"] if "~bpo" not in x["version"]
        ]

        if self.fixed == "(unfixed)":
            vulnerable_config = VulnerableConfig(
                version=known_versions[0], method="Vulnerable"
            )
            self.vulnerable.append(vulnerable_config)
        else:
            found = False
            for version, prev_version in zip(known_versions[:-1], known_versions[1:]):
                if version == self.fixed:
                    found = True
                    vulnerable_config = VulnerableConfig(
                        version=prev_version, method="N-1"
                    )
                    self.vulnerable.append(vulnerable_config)
                    break
            if not found:
                raise CVENotFound("Unable to find the preceding version")

        return self

    # HELPERS: of bug_version_lookup
    @staticmethod
    def _bugreport_mentions_cve(page_content, cve_number):
        cve_fullname = f"CVE-{cve_number}"
        debug(
            f"Checking if the CVE is mentioned in the bugreport\n"
            f"{cve_fullname} in page: {cve_fullname in page_content}"
        )
        if cve_fullname not in page_content:
            raise SearchError(
                "The bug linked to this cve through"
                " DSA doesn't seem to concern the current CVE"
            )

    @staticmethod
    def _extract_versions(page_content, bugid):
        soup = BeautifulSoup(page_content, "html.parser")
        bug_info = soup.find("div", class_="buginfo")
        if not bug_info or not isinstance(bug_info, Tag):
            raise CVENotFound(f"Could not find valid buginfo div for bug {bugid}")

        versions = []

        for p_tag in bug_info.find_all("p"):
            text = p_tag.get_text(strip=True)
            if text.startswith(("Found in version ", "Found in versions ")):
                version = text[len("Found in version ") :].strip().split(", ")
                versions.extend(version)
        debug(versions)

        return versions

    def _handle_versions(self, versions, dsa):
        # We treat cases where one bug report concerns many versions
        for version in versions:
            # We attempt to use the version without the backport
            # Works for CVE-2020-7247, should be tested further
            # We also remove the prepended packagename/
            match = re.search(r"(?:.*/)?([^\~]+?)(?:~bpo.*)?$", version)
            if match is not None:
                clean_version = match.group(1)
            else:
                clean_version = version

            vulnerable_config = VulnerableConfig(
                version=clean_version, method="Bug" if not dsa else "DSA"
            )

            assert self.vulnerable is not None
            self.vulnerable.append(vulnerable_config)
        if not versions:
            raise CVENotFound(f"bug { self.bugids} has no 'Found in version' tag")

    def bug_version_lookup(self, args, check=False):
        self.init_vulnerable()

        if self.bugids is None or self.vulnerable is None:
            raise SearchError(
                f"package {self.package} for {self.release} has no bugids"
            )

        for i, (bugid, used) in enumerate(self.bugids):
            if bugid < 40000:
                print(
                    f"The bugId : {bugid} might no longer be available, triying anyways"
                )

            if not used:
                self.bugids[i] = (bugid, True)
                url = f"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug={bugid}"
                try:
                    # This can be very slow
                    response = requests.get(url, timeout=DEFAULT_TIMEOUT * 6)
                    response.raise_for_status()
                    content = response.text

                    # Check if we find the CVE mentioned anywhere in the bug report
                    if check:
                        self._bugreport_mentions_cve(content, args.cve_number)
                    versions = self._extract_versions(content, bugid)
                    self._handle_versions(versions, check)

                except RequestException as error:
                    raise SearchError(
                        f"requests: Error accesing bug report: {error}"
                    ) from error

    def dsa_version_lookup(self, args):
        self.init_vulnerable()
        if self.bugids is None:
            self.bugids = []

        if self.advisory is None:
            raise SearchError(
                f"package: {self.package} for {self.release} has no DSA/DLA"
            )

        url = (
            f"https://www.debian.org/"
            f"{'lts/' if 'DLA' in self.advisory else ''}"
            f"security/{self.advisory}"
        )

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            pre_element = soup.find("pre")
            if not pre_element or not isinstance(pre_element, Tag):
                raise CVENotFound("requests: 'pre' tag not found on the page")
            advisory_text = pre_element.get_text(strip=True)

        except RequestException as exc:
            raise SearchError("Requests: Error accesing advisory") from exc

        # Find Bug Ids
        bug_pattern = r"Debian Bug\s*:\s*([\d\s]+)"
        bug_match = re.search(bug_pattern, advisory_text)
        bug_ids = bug_match.group(1).strip().split() if bug_match else []
        bug_ids = [(int(bugid), False) for bugid in bug_ids]
        if not bug_ids:
            raise CVENotFound("No Debian Bug IDs found in the security advisory")

        # Now that we found the bugIds we try and find a version behind these bugIds
        self.bugids.extend(bug_ids)
        self.bug_version_lookup(args, check=True)

    def vulnerable_versions_lookup(self, args):
        debug(f"\nFINDING version for: {self.package},{self.release}")
        try:
            debug("ATTEMTPING to find version with bugid")
            self.bug_version_lookup(args)
        except (SearchError, CVENotFound) as error:
            debug(f"BUGID failed with:\n\t{error}\n")
            debug("ATTEMPTING to find version with DSA")
            try:
                self.dsa_version_lookup(args)
            except (SearchError, CVENotFound) as error2:
                debug(f"DSA failed with:\n\t{error2}\n")

                # DSA lookup can find many bugids, which can fail
                # We only search with N-1 if all of them failed
                found_any = any(
                    config.method == "DSA"
                    for config in self.vulnerable
                    if self.vulnerable is not None
                )

                if not found_any:
                    debug("ATTEMPTING to find version with N-1")
                    try:
                        self.preceding_version_lookup()
                    except (SearchError, CVENotFound) as error3:
                        debug(f"N-1 failed with:\n\t{error3}")

    def choose_one(self):
        """
        Chooses the vulnerable config version that is closest to the fixed version,
        this collapses the vulnerable config list into a single element
        """
        bug_configs = []
        dsa_configs = []
        assert self.vulnerable is not None

        for vuln_config in self.vulnerable:
            if vuln_config.method == "Bug":
                bug_configs.append(vuln_config)
            if vuln_config.method == "DSA":
                dsa_configs.append(vuln_config)

        fixed_tuple = version_tuple(self.fixed)
        closest_to_fixed_bug = sorted(
            bug_configs,
            key=lambda cve: version_distance(version_tuple(cve.version), fixed_tuple),
        )
        closest_to_fixed_dsa = sorted(
            bug_configs,
            key=lambda cve: version_distance(version_tuple(cve.version), fixed_tuple),
        )

        if closest_to_fixed_bug != []:
            self.vulnerable = [closest_to_fixed_bug[0]]
        elif closest_to_fixed_dsa != []:
            self.vulnerable = [closest_to_fixed_dsa[0]]
        else:
            self.vulnerable = [self.vulnerable[0]]


def get_cve_tables(args: argparse.Namespace):
    url = f"https://security-tracker.debian.org/tracker/CVE-{args.cve_number}"
    fixed_table: Optional[Tag] = None
    info_table: Optional[Tag] = None

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, "html.parser")

        header_info = ["Source Package", "Release", "Version", "Status"]
        header_fixed = [
            "Package",
            "Type",
            "Release",
            "Fixed Version",
            "Urgency",
            "Origin",
            "Debian Bugs",
        ]

        info_tables = soup.find_all("table")  # Get all table tags
        for elt in info_tables:
            if info_tables is not None and isinstance(elt, Tag):
                header = [column.get_text() for column in elt.find_all("th")]
                if header == header_info:
                    info_table = elt
                if header == header_fixed:
                    fixed_table = elt

        if info_table == [] and fixed_table == []:
            raise CVENotFound(
                "Decret didn't find any tables on the security tracker site"
                " CVE is probably NOT-FOR-US or RESERVED"
            )

        info_table, fixed_table = clean_tables(info_table, fixed_table)
        info_table, fixed_table = filter_tables(info_table, fixed_table, args)

        if info_table == [] and fixed_table == []:
            if args.release is not None:
                message = ", seems like the specified release was never vulnerable"
            else:
                message = ""
            raise CVENotFound(
                "CVE is probably ITP this is not replicable"
                f"{message}"
                ", or the specified filtering is incorrect"
            )

    except RequestException as error:
        raise CVENotFound(f"{error}") from error

    return info_table, fixed_table


def clean_tables(info_table, fixed_table):
    if fixed_table != []:
        fixed_table = list(fixed_table.find_all("td"))
        fixed_table = [line.get_text() for line in fixed_table]
        fixed_table = [fixed_table[i : i + 7] for i in range(0, len(fixed_table), 7)]
    else:
        fixed_table = []

    if info_table != []:
        info_table = list(info_table.find_all("td"))
        info_table = [line.get_text() for line in info_table]
        info_table = [info_table[i : i + 4] for i in range(0, len(info_table), 4)]
    else:
        info_table = []

    current_package = ""
    for line in info_table:
        if line[0] != "":
            line[0] = "".join(line[0].split(" (PTS)"))
            current_package = line[0]
        elif line[0] == "":
            line[0] = current_package

    return info_table, fixed_table


def filter_tables(info_table, fixed_table, args):
    fixed_table = [
        line
        for line in fixed_table
        if "(not affected)" not in line
        and (not args.release or args.release in line)
        and any(release in line for release in DEBIAN_RELEASES + ["(unstable)"])
    ]

    info_table = [
        line
        for line in info_table
        if (
            "(security)" not in line
            and "vulnerable" in line
            and any(release in line for release in DEBIAN_RELEASES)
        )
    ]

    return info_table, fixed_table


# pylint: disable=too-many-positional-arguments
def convert_tables(info_table, fixed_table):
    convert_results = []

    for line in fixed_table:
        try:
            bug_id = int(line[6])
        except ValueError:
            bug_id = None

        config = Cve(
            package=line[0],
            release="sid" if line[2] == "(unstable)" else line[2],
            fixed=line[3],
            advisory=None if line[5] == "" else line[5],
            bugids=None if bug_id is None else [(bug_id, False)],
            vulnerable=[],
        )
        convert_results.append(config)

    # If there's a line here, it means the release concerned by this line is vulnerable
    # see: filter_table
    for line in info_table:
        vulnerable_config = VulnerableConfig(version=line[2], method="Vulnerable")
        config2 = Cve(package=line[0], release=line[1], vulnerable=[vulnerable_config])
        convert_results.append(config2)

    for config in convert_results:
        debug(f"{config.to_string()}\n")

    return convert_results


def versions_lookup(cve_list, args):
    # might be smart to use flags to filter which method to use
    for cve in cve_list:
        if cve.vulnerable == []:
            cve.vulnerable_versions_lookup(args)


def get_snapshots(cve_list, args):
    for cve in cve_list:
        for config in cve.vulnerable:
            try:
                config.get_hash_and_bin_names(args, cve.package)
                config.get_snapshot()
            except SearchError as error:
                debug(f"failed to get snapshot with: {error}")
                cve.vulnerable.remove(config)


def collapse_list(cve_list, args):
    # For the time being if a bug report has many affected versions we take the first one:
    # And we filter out unwanted packages
    collapsed = []
    for cve in cve_list:
        if args.bin_package is not None and args.bin_package not in cve.package:
            continue
        cve.choose_one()
        collapsed.append(cve)
    return collapsed


def choose_one(collapsed_list):
    # The idea here is to choose the most reliable method with the most recent release
    # we use the lexicographical comparison of python tuples for this
    # this goes through all the CVE list,
    # but supposes the vulnerable config is one element instead of a list

    best = max(
        collapsed_list,
        key=lambda x: (
            METHOD_PRIORITY[x.vulnerable[0].method],
            RELEASE_PRIORITY[x.release],
        ),
    )

    return best


def display_options(cve_list):
    print("Found the following configurations: ")
    for i, cve in enumerate(cve_list, start=1):
        if len(cve.vulnerable) > 1:
            print(f"{i} Release: {cve.release}, Package: {cve.package}")
            for x, vuln_config in enumerate(cve.vulnerable, start=1):
                print(f"  {x}: Version: {vuln_config.version}")
        else:
            print(
                f"{i} Release: {cve.release}",
                f"Package: {cve.package}",
                f"Version: {cve.vulnerable[0].version}",
            )


def choose_manually(cve_list):
    choice = input("Choose a configuration (e.g. 2 or 1.2): ")
    parts = choice.split(".")

    try:
        if len(parts) == 1:
            chosen_cve = cve_list[int(parts[0]) - 1]
            if int(parts[0]) < 1:
                raise ValueError("Index must be >= 1")
            if len(chosen_cve.vulnerable) > 1:
                raise ValueError("This CVE has multiple choices")
            return chosen_cve

        if len(parts) == 2:
            if int(parts[0]) < 1 or int(parts[1]) < 1:
                raise ValueError("Both indices must be >= 1")
            chosen_cve = cve_list[int(parts[0]) - 1]
            if len(chosen_cve.vulnerable) == 1:
                raise ValueError("The chosen CVE doesn't have multiple choices")
            chosen_config = chosen_cve.vulnerable[int(parts[1]) - 1]
            chosen_cve.vulnerable = [chosen_config]
            return chosen_cve
        # If parts is not length 1 or 2, treat as invalid input
        raise ValueError("Invalid input format")

    except (IndexError, ValueError):
        return choose_manually(cve_list)


def cache_to_json(cve_list, cve_number):
    os.makedirs(CACHE_PATH, exist_ok=True)

    data = {"cve_list": [cve.to_dict() for cve in cve_list]}

    file_path = CACHE_PATH / f"{cve_number}.json"
    with open(file_path, "w", encoding="utf-8") as file:
        json.dump(data, file, indent=2)


def load_from_json(cve_number):
    file_path = CACHE_PATH / f"{cve_number}.json"
    with open(file_path, "r", encoding="utf-8") as file:
        data = json.load(file)
    cve_list = data.get("cve_list", [])
    cve_list = [Cve.from_dict(data) for data in cve_list]
    return cve_list


def handle_data_retrieval(args):
    """
    This function handles how data is retrieved, either through the cache or
    web lookup, it also handles updating the cache.
    returns a list of Cve objects
    """
    cves = None

    if not args.no_cache_lookup:
        try:
            cves = load_from_json(args.cve_number)
            print("Loaded CVE data from cache, to disable use --no-cache-lookup\n")
        except FileNotFoundError:
            print("No cached file found, performing table lookup.")
        except json.JSONDecodeError as e:
            print(f"Failed to load cached file: {e}, performing table lookup.")

    if cves is None:
        try:
            print(
                "\nGetting information from:\n",
                "https://security-tracker.debian.org"
                f"/tracker/CVE-{args.cve_number}\n",
            )
            info_table, fixed_table = get_cve_tables(args)
        except CVENotFound as error:
            raise CVENotFound from error

        if args.release and args.choose:
            print(
                "Warning: --release filtering applied, "
                "cache file will only store table entries for this release\n"
                "loading from cache can be disabled with --no-cache-lookup, "
                "this also updates the cache\n"
            )
        cves = convert_tables(info_table, fixed_table)

        print("Doing version and snapshot lookup\n")
        versions_lookup(cves, args)
        get_snapshots(cves, args)
        print("Caching results\n")
        cache_to_json(cves, args.cve_number)

    return cves


def main():
    arguments = init_decret()

    try:
        cves = handle_data_retrieval(arguments)
    except CVENotFound as error:
        print(f"Failed to retrieve data for this CVE with: {error}")
        return

    if arguments.choose:
        display_options(cves)
        choice = choose_manually(cves)
        collapsed_list = collapse_list(cves, arguments)
    else:
        collapsed_list = collapse_list(cves, arguments)
        total = len(collapsed_list)
        print(f"Found {total} possible configurations")
        choice = choose_one(collapsed_list)
        print(
            "My best guess is:\n",
            f"Release {choice.release}\n",
            f"Package {choice.package}\n",
            f"Version {choice.vulnerable[0].version}\n",
            f"Method {choice.vulnerable[0].method}\n",
        )

    if not arguments.release:
        arguments.release = choice.release

    vuln_unfixed = choice.vulnerable[0].version == "(unfixed)"

    # The second arg helps chosing wether or not using snapshot
    source_lines = prepare_sources(
        choice.vulnerable[0].timestamp, not vuln_unfixed or arguments.release == "sid"
    )

    if vuln_unfixed:
        print(f"\n\nVulnerability unfixed. Using a {LATEST_RELEASE} container.\n\n")
        arguments.release = LATEST_RELEASE

    download_db()
    get_exploits(arguments)

    print("Writing Dockerfile")
    write_dockerfile(arguments, collapsed_list, source_lines)
    write_cmdline(arguments)

    if arguments.only_create_dockerfile:
        print("My work here is done.")
        return

    build_docker(arguments)

    if arguments.dont_run or RUNS_ON_GITHUB_ACTIONS:
        print("My work here is done.")
        return
