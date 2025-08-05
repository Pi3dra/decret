import re
import pytest
from decret.decret import argparse, CVENotFound, DEBIAN_RELEASES, handle_data_retrieval


# ===================== TESTING Finding and cleaning Tables =====================


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


def test_should_fail():
    # CVE-2005-2433 (itp)
    # CVE-2002-0807 (NO TABLES)
    # CVE-2006-2625 (Reserved)
    # CVE-2021-4134 (Not for us)
    test = ["2005-2433", "2002-0807", "2006-2625", "2021-4134"]
    for cve_number in test:
        args = argparse.Namespace()
        args.cve_number = cve_number
        args.no_cache_lookup = False
        args.release = None
        with pytest.raises(CVENotFound):
            handle_data_retrieval(args)


# ===================== TESTING Conversion to cve object list =====================


# pylint:disable=too-many-arguments, too-many-positional-arguments
def check_cve(config, package, release, fixed, advisory, bugid):
    return (
        config.package == package
        and config.release == release
        and config.fixed == fixed
        and config.advisory == advisory
        and (config.bugids is None or any(bug == bugid for bug in config.bugids))
    )


def test_converted_list(converted_tables):
    # Given that the previous tests ensure correctness
    # and this only converts the list into objects
    # we can now verify we got the information we wanted

    # Might be smart to do this on static examples so it works
    # without webpage

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

    cve = results[1]

    # This verifies the proper amount of
    # vulnerable configurations is found
    check_counts(results[0], 1, 0, 7, 5)
    print(results[0])
    assert cve["2020-7247"]
    assert cve["2014-0160"]
    assert cve["2021-3156"]
    assert cve["2020-35448"]


# Timestamps should probably be tested as well...


# ===================== TESTING Version Choices =====================
def test_collapsed_list(collapsed_lists):
    # The idea here is to keep a single promising configuration for each entry
    assert len(collapsed_lists) > 0
    for cve_list in collapsed_lists.values():
        for cve in cve_list:
            assert len(cve.vulnerable) == 1


def test_choice(chosen_configs):
    expected_results = {
        "2020-7247": ("opensmtpd", "sid", "6.6.1p1-5", "Bug"),
        "2014-0160": ("openssl", "sid", "1.0.1f-1", "Bug"),
        "2021-3156": ("sudo", "buster", "1.8.27-1+deb10u2", "N-1"),
        "2020-35448": ("binutils", "bullseye", "2.35.2-2", "Vulnerable"),
    }
    for cve_number, chosen_config in chosen_configs.items():
        package = expected_results[cve_number][0]
        release = expected_results[cve_number][1]
        vuln_version = expected_results[cve_number][2]
        method = expected_results[cve_number][3]
        assert (
            chosen_config.package == package
            and chosen_config.release == release
            and chosen_config.vulnerable[0].version == vuln_version
            and chosen_config.vulnerable[0].method == method
        )
