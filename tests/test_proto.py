import pytest
from decret.proto import *
import re

# ===================== Global Fixtures =====================


@pytest.fixture(scope="session")
def cve_numbers():
    file_path = "tests/test-material/test.txt"
    try:
        with open(file_path, "r") as file:
            return [line.strip() for line in file if line.strip()]
    except Exception as e:
        pytest.fail(f"Error reading CVE file: {str(e)}")


# ===================== TESTING Finding and cleaning Tables =====================


@pytest.fixture(scope="session")
def found_tables(cve_numbers):
    results = {}
    errored_on_search = []

    for cve_number in cve_numbers:
        args = argparse.Namespace()
        args.cve_number = cve_number
        args.release = None

        try:
            info_table, fixed_table = get_cve_tables(args)
            results[cve_number] = (info_table, fixed_table)
        except Exception as e:
            errored_on_search.append((cve_number, e))
            continue
    return results


@pytest.fixture(scope="session")
def filtered_tables(found_tables):
    results = {}
    args = argparse.Namespace()
    args.release = False
    for cve, (info_table, fixed_table) in found_tables.items():
        info_table, fixed_table = filter_tables(info_table, fixed_table, args)
        results[cve] = (info_table, fixed_table)
    return results


validation_rules_fixed = [
    lambda val: val != "",  # Package: non-empty
    lambda val: val != "",  # Source: non-empty
    lambda val: any(
        val.startswith(release) for release in DEBIAN_RELEASES + ["(unstable)"]
    ),  # Release
    lambda val: val in ["(unfixed)", "(not affected)"] or val != "",  # Fixed
    lambda val: val
    in ["unimportant", "low", "medium", "high", "end-of-life", ""],  # Urgency
    lambda val: val == "" or val.startswith("DSA") or val.startswith("DLA"),  # Origin
    lambda val: val == "" or re.fullmatch(r"\d+", val) is not None,  # Bug
]

validation_rules_info = [
    lambda val: val != "",  # Package
    lambda val: any(
        val.startswith(release) for release in DEBIAN_RELEASES + ["(unstable)"]
    ),  # Release
    lambda val: val != "",  # Version
    lambda val: val in ["fixed", "vulnerable"],  # Status
]


def test_searching_tables(found_tables):
    # We verify that each element corresponds to the preceding rules
    # The idea is to extract the WHOLE tables
    # These tests might seem strict, but the idea is
    # to ensure we get the most information possible
    # so it is easier to re-use information for new strategies
    # so no filtering should be applied at this stage

    for cve_number, (info_list, fixed_list) in found_tables.items():
        for line in fixed_list:
            assert len(line) == 7
            for i, val in enumerate(line):
                assert validation_rules_fixed[i](
                    val
                ), f"CVE-{cve_number}: Invalid value: '{val}' in position {i}"

        for line in info_list:
            assert len(line) == 4
            for i, val in enumerate(line):
                assert validation_rules_info[i](
                    val
                ), f"CVE-{cve_number}: Invalid value: '{val}' in position {i}"


def test_filterting_tables(filtered_tables):
    # This is susceptible to change when different things get implemented
    for _, (info_list, fixed_list) in filtered_tables.items():
        for line in fixed_list:
            assert len(line) == 7
            assert "(not affected)" not in line

        for line in info_list:
            assert len(line) == 4
            assert "fixed" not in line
            assert "(security)" not in line  # Not yet implemented


# ===================== TESTING Conversion to cve object list =====================


@pytest.fixture(scope="session")
def converted_tables(filtered_tables):
    results = {}
    for cve, (info_table, fixed_table) in filtered_tables.items():
        cve_list = convert_tables(info_table, fixed_table)
        results[cve] = cve_list
    return results


def check_cve(config, package, release, fixed, advisory=None, bugid=None):
    return (
        config.package == package
        and config.release == release
        and config.fixed == fixed
        and config.advisory == advisory
        and (config.bugids is None or any(bug[0] == bugid for bug in config.bugids))
    )


def test_converted_list(converted_tables):
    # Given that the previous tests ensure correctness
    # and this only converts the list into objects
    # we can now verify we got the information we wanted

    # Might be smart to do this on static examples so it works
    # without webpage

    # TODO: CHECK EDGE CASES
    # CVE-2005-2433 (itp)
    # CVE-2002-0807 (NO TABLES)
    # CVE-2006-2625 (Reserved)
    # CVE-2021-4134 (Not for us)

    cve = converted_tables

    tests = {
        "2020-7247": [
            ("opensmtpd", "stretch", "6.0.2p1-2+deb9u2", "DSA-4611-1", None),
            ("opensmtpd", "buster", "6.0.3p1-5+deb10u3", "DSA-4611-1", None),
            ("opensmtpd", "sid", "6.6.2p1-1", None, 950121),
        ],
        "2014-0160": [
            ("openssl", "wheezy", "1.0.1e-2+deb7u5", "DSA-2896-1", None),
            ("openssl", "sid", "1.0.1g-1", None, 743883),
        ],
        "2021-3156": [
            ("sudo", "stretch", "1.8.19p1-2.1+deb9u3", "DLA-2534-1", None),
            ("sudo", "buster", "1.8.27-1+deb10u3", "DSA-4839-1", None),
            ("sudo", "sid", "1.9.5p1-1.1", None, None),
        ],
        # This cve is flagged as unimportant and not susceptible to being fixed
        # The purpose of this one is to validate that currently vulnerable configs
        # are handled correctly see: last assert
        "2020-35448": [
            ("binutils", "sid", "2.37-3", None, None),
            # We consider vulnerable releases to have no fixed versions
            # the vulenrable config would be inside cve.vulnerable
            ("binutils", "bullseye", None, None, None),
        ],
    }

    for cve_number, expected_entries in tests.items():
        assert cve[cve_number]
        # We make sure that the list has exactly the specified cases
        assert len(cve[cve_number]) == len(expected_entries)

        for package, release, fixed, advisory, bugids in expected_entries:
            print(
                f"{cve_number}: \n "
                f"{' '.join([cve.to_string() for cve in cve[cve_number]])}\n"
                f"{package} {release} {fixed} {advisory} {bugids}"
            )
            assert any(
                check_cve(cve, package, release, fixed, advisory, bugids)
                for cve in cve[cve_number]
            ), (
                f"{cve_number}: \n "
                f"{' '.join([cve.to_string() for cve in cve[cve_number]])}\n"
                f"{package} {release} {fixed} {advisory} {bugids}"
            )

    assert any(len(cve.vulnerable) > 0 for cve in cve["2020-35448"])


# ===================== TESTING Finding Vulnerable versions =====================


@pytest.fixture(scope="session")
def vuln_configs(converted_tables):
    for cve_number, cve_list in converted_tables.items():
        args = argparse.Namespace()
        args.cve_number = cve_number

        versions_lookup(cve_list, args)

    return converted_tables


def count_configs(vuln_configs):
    counter = {"Vulnerable": 0, "DSA": 0, "N-1": 0, "Bug": 0}
    results = {}

    for cve_number, cve_list in vuln_configs.items():
        counter2 = {"Vulnerable": 0, "DSA": 0, "N-1": 0, "Bug": 0}
        for cve in cve_list:
            for config in cve.vulnerable:
                counter2[config.method] += 1
                counter[config.method] += 1
        results[cve_number] = counter2

    return (counter, results)


def check_counts(count, vuln, dsa, preceding, bug):
    return (
        count["Vulnerable"] == vuln
        and count["DSA"] == dsa
        and count["N-1"] == preceding
        and count["Bug"] == bug
    )


def test_finding_vuln_configs(vuln_configs):
    results = count_configs(vuln_configs)

    # is a global counter really useful?
    cve = results[1]

    # For the time being we only reason based on
    # the number of vulnerable configs found and the
    # methods used, not if the version is vulnerable or not,
    # I have yet to implement how to choose the best vulnerable config
    check_counts(results[0], 1, 0, 7, 5)
    print(results[0])
    assert cve["2020-7247"]
    assert cve["2014-0160"]
    assert cve["2021-3156"]
    assert cve["2020-35448"]
