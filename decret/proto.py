import argparse
import time  # ERASE, this is for testing only
import os
import re
import pandas as pd
from bs4 import BeautifulSoup, Tag
from requests.exceptions import RequestException
from decret.decret import (
    requests,
    DEFAULT_TIMEOUT,
    DEBIAN_RELEASES,
    FatalError,
    CVENotFound,
    Path,
    sys,
)


DEBUG = False


class SearchError(BaseException):
    pass


def debug(string):
    if DEBUG:
        print(string)


class VulnerableConfig:
    def __init__(self, version, method):
        self.version = version
        self.timestamp = None
        self.method = method
        self.pkg_hash = None
        self.bin_names = None

    def to_string(self):
        return (
            f"  version: {self.version}\n "
            f"   timestamp: {self.timestamp}\n "
            f"   method: {self.method}\n"  # [bug,DSA,n-1,still_vulnerable]
        )

    def get_bin_names(self, package):
        bin_names = []
        url = (
            f"http://snapshot.debian.org/mr/package"
            f"/{package}/{self.version}/binpackages"
        )

        try:
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            response = response.json()["result"]
            for res in response:
                bin_names.append(res["name"])
        except requests.exceptions.RequestException as err:
            print(f"get_bin_names failed with: {err}")

    def get_hash_and_bin_names(self, args, package):
        try:
            url = (
                f"http://snapshot.debian.org/mr/binary"
                f"/{package}/{self.version}/binfiles"
            )

            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            response = response.json()["result"]
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
                response = requests.get(url, timeout=DEFAULT_TIMEOUT)
                response.raise_for_status()
                response = response.json()["result"]

                self.pkg_hash = response[-1]["hash"]
                self.get_bin_names(package)
            except Exception as error2:
                raise SearchError(
                    f"Couldn't find the source files for the linux package {package} with {error},."
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
            response = requests.get(url, timeout=DEFAULT_TIMEOUT)
            response.raise_for_status()
            response = response.json()["result"][-1]
            self.timestamp = response["first_seen"]
        except (requests.exceptions.RequestException, KeyError) as error:
            raise SearchError(f"failed to find snapshot with: {error}") from error


class Cve:
    # pylint: disable=too-many-arguments
    def __init__(
        self,
        package=None,
        release=None,
        fixed=None,
        advisory=None,
        bugids=None,
        vulnerable=None,  # TODO: this shouldn't be a list, as we only keep one
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
            f"vulnerable:\n{vuln_version_strs}"
            f"advisory:\n  {self.advisory}\n "
            f"bugids:  {self.bugids} \n "
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

    # This could be cleaner with an iterator handling the bugids
    # TODO: Split this
    #pylint: disable=(too-many-locals)
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
                    response = requests.get(url, timeout=DEFAULT_TIMEOUT)
                    response.raise_for_status()
                    content = response.text

                    # Check if we find the CVE mentioned anywhere in the bug report
                    if check:
                        cve_fullname = f"CVE-{args.cve_number}"
                        debug(
                            f"Checking if there's a DSA->bug->link\n"
                            f"{cve_fullname} in page: {cve_fullname in content}"
                        )
                        if cve_fullname not in content:
                            raise CVENotFound(
                                "The bug linked to this cve through"
                                "DSA doesn't seem to concern the current CVE"
                            )
                    soup = BeautifulSoup(content, "html.parser")
                    bug_info = soup.find("div", class_="buginfo")
                    if not bug_info or not isinstance(bug_info, Tag):
                        raise CVENotFound(
                            f"Could not find valid buginfo div for bug {bugid}"
                        )

                    versions = []

                    for p_tag in bug_info.find_all("p"):
                        text = p_tag.get_text(strip=True)
                        if text.startswith(("Found in version ", "Found in versions ")):
                            version = (
                                text[len("Found in version ") :].strip().split(", ")
                            )
                            versions.extend(version)
                    debug(versions)

                    # We treat cases where one bug concerns many versions
                    # TODO: Handle cases where the packagename is prepended to the version
                    for version in versions:
                        vulnerable_config = VulnerableConfig(
                            version=version, method="Bug" if not check else "DSA"
                        )
                        self.vulnerable.append(vulnerable_config)
                    if not versions:
                        raise CVENotFound(
                            f"bug { self.bugids} has no 'Found in version' tag"
                        )

                except RequestException as exc:
                    raise SearchError("requests: Error accesing bug report") from exc

    def dsa_version_lookup(self, args):
        # TODO: Investigate, some old DSAs are no longer available? CVE-2002-1051
        self.init_vulnerable()
        if self.bugids is None:
            self.bugids = []

        if self.advisory is None or self.vulnerable is not None:
            raise SearchError(
                f"package: {self.package} for {self.release} has no DSA/DLA"
            )

        url = (
            f"https://www.debian.org/"
            f"{'lts/' if 'DSA' in self.advisory else ''}"
            "security/{self.advisory}"
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
        # TODO: Refactor this to send an error if a version isn't found,
        # This way it can be filtered

        try:
            self.bug_version_lookup(args)
        except (SearchError, CVENotFound) as error:
            debug(f"finding vulnerable version for: {self.package},{self.release}")
            debug(f"Finding version through bugid failed with:\n\t{error}")
            if self.advisory:
                debug("\tattempting to find version using DSAs")
                try:
                    self.dsa_version_lookup(args)
                except (SearchError, CVENotFound) as error2:
                    debug(
                        f"\t\tFinding version through DSAs failed with:\n\t\t\t{error2}"
                        "\t\t\tattempting to find the preceding version of the fixed one"
                    )
                    try:
                        self.preceding_version_lookup()
                    except (SearchError, CVENotFound) as _:
                        debug(
                            f"\t\t\t\tThis package: {self.package} is currently vulnerable"
                        )
            else:
                debug("\tattempting to find the preceding version of the fixed one")
                try:
                    self.preceding_version_lookup()
                except (SearchError, CVENotFound):
                    debug(f"\t\tthis package: {self.package} is currently vulnerable")


def get_cve_tables(args: argparse.Namespace):
    url = f"https://security-tracker.debian.org/tracker/CVE-{args.cve_number}"
    fixed_table = None
    info_table = None
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

        if info_table is None and fixed_table is None:
            raise CVENotFound(
                "Decret didn't find any tables on the security tracker site"
            )

        info_table, fixed_table = clean_tables(info_table, fixed_table)
        info_table, fixed_table = filter_tables(info_table, fixed_table)

        if info_table is None and fixed_table is None:
            raise CVENotFound(
                "CVE is either ITP,NOT-FOR-US,REJECTED, or it doesn't affect any debian release"
            )
    except RequestException as error:
        print(f"Failed to retrieve CVE data from {url}: {error}")

    return info_table, fixed_table


def clean_tables(info_table, fixed_table):
    if fixed_table is not None:
        fixed_table = list(fixed_table.find_all("td"))
        fixed_table = [line.get_text() for line in fixed_table]
        fixed_table = [fixed_table[i : i + 7] for i in range(0, len(fixed_table), 7)]
    else:
        fixed_table = []

    if info_table is not None:
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


def filter_tables(info_table, fixed_table):
    # The idea of filtering separately is to have all available data and
    # make it easier for implementig other stuff
    # also for handling args like --release
    fixed_table = [
        line
        for line in fixed_table
        # TODO: Implement support for (unstable)
        if "(not affected)" not in line and
        # This line might not be useful
        any(release in line for release in DEBIAN_RELEASES)
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


def convert_tables(info_table, fixed_table):
    convert_results = []

    for line in fixed_table:
        try:
            bug_id = int(line[6])
        except ValueError:
            bug_id = None

        config = Cve(
            package=line[0],
            release=line[2],
            fixed=line[3],
            advisory=None if line[5] == "" else line[5],
            bugids=None if bug_id is None else [(bug_id, False)],
            vulnerable=[],
        )
        convert_results.append(config)

    # If there's a line here, it means the release concerned by this line is vulnerable
    # see: filter_table
    for line in info_table:
        vulnerable_config = VulnerableConfig(version=line[2], method="vulnerable")
        config2 = Cve(package=line[0], release=line[1], vulnerable=[vulnerable_config])
        convert_results.append(config2)

    for config in convert_results:
        debug(f"{config.to_string()}\n")

    return convert_results


def versions_lookup(cve_list, args):
    # might be smart to use flags to filter which method to use
    for cve in cve_list:
        cve.vulnerable_versions_lookup(args)


def get_snapshots(cve_list, args):
    for cve in cve_list:
        for config in cve.vulnerable:
            try:
                config.get_hash_and_bin_names(cve.package, args)
                config.get_snapshot()
            except SearchError as error:
                debug(f"failed to get snapshot with: {error}")
                cve_list.remove(cve)


def db_is_up_to_date():
    """
    Returns a tuple ( bool * string) indicating if the db needs updating and the new hash
    """
    project_id = "40927511"  # Project ID for exploit-db
    file_path = "files_exploits.csv"
    destination_dir = "cached-files"
    hash_file_path = os.path.join(destination_dir, "files_exploits.hash")
    url = (
        f"https://gitlab.com/api/v4/projects/{project_id}"
        f"/repository/files/{file_path}/raw?ref=main"
    )

    # TODO: Test this further, curl needs 0,5s
    # meanwhile this takes 10 secs to get a HEAD request
    # Maybe it's my pc lol
    start = time.perf_counter()
    head = requests.head(url, timeout=DEFAULT_TIMEOUT)
    duration = time.perf_counter() - start
    print(f"HEAD request took: {duration:.2f} seconds")
    head.raise_for_status()
    blob_hash = head.headers["x-gitlab-blob-id"]

    stored_blob_hash = None

    try:
        with open(hash_file_path, "r", encoding="utf-8") as file:
            stored_blob_hash = file.read()
    except FileNotFoundError:
        return (False, blob_hash)

    return (stored_blob_hash == blob_hash, blob_hash)


def download_db():
    # DOCS: https://docs.gitlab.com/api/repository_files/#get-file-metadata-only
    project_id = "40927511"  # Project ID for exploit-db
    file_path = "files_exploits.csv"
    destination_dir = "cached-files"
    hash_file_path = os.path.join(destination_dir, "files_exploits.hash")
    csv_file_path = os.path.join(destination_dir, file_path)
    url = (
        f"https://gitlab.com/api/v4/projects/{project_id}"
        f"/repository/files/{file_path}/raw?ref=main"
    )

    try:
        up_to_date, blob_hash = db_is_up_to_date()
    except RequestException as error:
        print(f"Checking if the db is up to date failed with {error}")
        return

    if not up_to_date:
        print("Proceeding to download files_exploits.csv from exploit-db")
    else:
        print("db is up to date no need to download it")
        return

    try:
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        response.raise_for_status()
    except RequestException as error:
        print(f"Failed GET request from {url} with :\n{error}")
        return

    os.makedirs(destination_dir, exist_ok=True)

    try:
        with open(csv_file_path, "wb") as file:
            file.write(response.content)
        with open(hash_file_path, "w", encoding="utf-8") as file:
            file.write(blob_hash)
        print("File downloaded and hash updated.")
    except IOError as error:
        print(f"Failed to write file: {error}")


def get_exploit(args):
    try:
        data = pd.read_csv("cached-files/files_exploits.csv")
    except FileNotFoundError:
        download_db()
        try:
            data = pd.read_csv("cached-files/files_exploits.csv")
        except FileNotFoundError:
            print("Failed to download db")
            return

    data = data[["id", "file", "verified", "codes", "tags", "aliases"]]

    cve_id = f"CVE-{args.cve_number}"
    # quel bonheur
    data = data[
        data["codes"].str.contains(cve_id, na=False)
        | data["tags"].str.contains(cve_id, na=False)
        | data["aliases"].str.contains(cve_id, na=False)
    ]
    data = list(zip(data["id"], data["file"], data["verified"]))

    output_dir = Path(args.directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    if len(data) == 0:
        print("No exploits Found")
        return

    for i, (exploit_id, path, verified) in enumerate(data):
        # Building url
        project_id = "40927511"
        url = (
            f"https://gitlab.com/api/v4/projects/{project_id}"
            f"/repository/files/{path.replace('/', '%2F')}/raw?ref=main"
        )

        # Building path
        file_extension = os.path.splitext(path)[1]
        exploit_filename = f"exploit_{i}_{exploit_id}"
        if verified:
            exploit_filename += "_verified"
        exploit_path = output_dir / Path(exploit_filename + file_extension)

        # Fetching exploits
        response = requests.get(url, timeout=DEFAULT_TIMEOUT)
        if response.status_code == 200:
            os.makedirs("cached-files", exist_ok=True)
            with open(exploit_path, "wb") as file:
                file.write(response.content)
        else:
            print(f"Failed to download file: {response.status_code} - {response.text}")


if __name__ == "__main__":
    # TODO: Understand how we deal with the (unfixed) tag now
    # TODO: cve.vulnerable shouldn't be a list
    # TODO: fix bug_lookup
    try:
        arguments = argparse.Namespace()
        arguments.cve_number = "2016-3714"
        arguments.directory = "hey_listen!"

        """

        info_table, fixed_table = get_cve_tables(args)
        cve_list = convert_tables(info_table, fixed_table)
        versions_lookup(cve_list, args)

        print("\nResults: \n")
        for cve in cve_list:
            print(f"{cve.to_string()}\n")
        """
        download_db()
        # get_exploit(args)

    except FatalError as fatal_exc:
        print(fatal_exc, file=sys.stderr)
        sys.exit(1)
