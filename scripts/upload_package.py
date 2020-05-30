#!/usr/bin/env python3.8

import argparse
import subprocess
import re
import sys
import logging
from pathlib import Path

import svarmi.cryptography._utils as utils
import svarmi.cryptography._logging as svarmi_logger


def main():
    args = parse_arguments()
    svarmi_logger.configure(logging.DEBUG)

    package_directory = get_package_directory()
    package_version = get_package_version()

    if is_git_working_dir_dirty():
        print(
            "\nUnable to upload because the package's git working tree "
            + "is dirty.\nBefore uploading, please commit any changes "
            + "you have made by running:\n\ngit add .\ngit commit"
        )
        sys.exit(1)

    if is_pre_release_version(package_version):
        print(
            "\nUnable to upload because current version is a pre-release version, "
            + "which are forbidden on SPyPi.\n"
        )
        print(f"Current version is:\n'{package_version}'\n")

        (major, minor, patch) = get_version_parts(package_version)

        last_version = f"{major}.{minor}.{patch - 1}"
        next_patch_version = f"{major}.{minor}.{patch}"
        next_minor_version = f"{major}.{minor + 1}.{0}"
        next_major_version = f"{major + 1}.{0}.{0}"

        print(
            f"Last version was '{last_version}', "
            + "do you want to create a new version for the package?"
        )
        print(f"(1) Yes, create version '{next_patch_version}'")
        print(f"(2) Yes, create version '{next_minor_version}'")
        print(f"(3) Yes, create version '{next_major_version}'")
        print("(4) No")
        print("Enter your choice [1/2/3/4]:")
        choice = int(input())
        assert choice in [1, 2, 3, 4]
        print()

        choice_map = {
            1: next_patch_version,
            2: next_minor_version,
            3: next_major_version,
            4: None,
        }
        version_to_create = choice_map[choice]

        if version_to_create is None:
            return

        vers = version_to_create
        logging.info(f"Creating version {vers} ...")
        utils.try_cmd(f"git tag -a 'v{vers}' -m 'Release version {vers}'")

        package_version = get_package_version()
        assert not is_pre_release_version(package_version)

    pd = get_package_directory()

    logging.info("Pushing changes to GitLab, also pushing tags ...")
    utils.try_cmd("git push --follow-tags", cwd=pd)

    logging.info("Building package ...")
    utils.cmd("rm dist/*", cwd=pd)
    utils.try_cmd("python3.8 setup.py sdist bdist_wheel", cwd=pd)

    logging.info("Checking package integrity ...")
    utils.try_cmd("python3.8 -m twine check dist/*", cwd=pd)

    logging.info("Checking that unit tests succeed ...")
    utils.try_cmd("tox -e unit", cwd=pd)

    logging.info("Checking that integration tests succeed ...")
    utils.try_cmd("tox -e integration", cwd=pd)

    logging.info("Uploading package!")
    utils.try_cmd("python3.8 -m twine upload -r spypi dist/*", cwd=pd)

    logging.info("Upload successful")


def parse_arguments():
    parser = argparse.ArgumentParser()
    parser.description = (
        "This scripts uploads this package to SPyPi (spypi.svarmi.is). "
        "Before uploading it guides you through any necessary steps you need to do "
        + "to to update the version of the package. The scripts also makes sure unit-"
        + "and integration tests pass before uploding and it also pushes changes "
        + "to GitLab so you don't forget to 'git push --follow-tags'"
    )
    arguments = parser.parse_args()
    return arguments


def is_git_working_dir_dirty():
    results = utils.try_cmd(
        "git status", cwd=get_package_directory(), capture_output=True
    )
    output = results.stdout.decode()

    is_unstaged_changes = re.search("Changes not staged for commit", output)
    is_untracked_files = re.search("Untracked files", output)

    return is_unstaged_changes or is_untracked_files


def is_pre_release_version(version):
    return "dev" in version


def get_version_parts(version):
    match = re.match("(\d+)\.(\d+)\.(\d+).*", version)
    if match:
        (major, minor, patch) = map(int, match.groups())
        return (major, minor, patch)

    match = re.match("(\d+)\.(\d+)\.dev(\d+)\+.*", version)
    if match:
        (major, minor, patch) = map(int, match.groups())
        return (major, minor, patch)

    raise RuntimeError(f"Unable to version parts for version '{version}'")


def get_package_version():
    results = utils.try_cmd(
        "python3.8 setup.py --version",
        cwd=get_package_directory(),
        capture_output=True,
    )
    return results.stdout.decode().rstrip()


def get_package_directory():
    return Path(__file__).resolve().parent.parent


if __name__ == "__main__":
    main()
