import os
import re
import importlib
import importlib.resources
import logging
from pathlib import Path


def run(challenge_num):
    logging.info(f"Running challenge {challenge_num} ...")
    challenge_module_name = _get_challenge_module_name(challenge_num)
    import_path = f"drvn.cryptography_challenges.{challenge_module_name}"

    challenge_module = importlib.import_module(import_path)
    challenge_module.run_challenge()


def _get_challenge_module_name(challenge_num):
    challenge_modules = _get_challenge_modules()
    challenge_modules.sort()

    if challenge_num < 1 or challenge_num > len(challenge_modules):
        raise ValueError(f"Challenge {challenge_num} does not exist.")
    challenge_module = challenge_modules[challenge_num - 1]
    return challenge_module


def _get_challenge_modules():
    modules = _get_package_modules()
    challenge_modules = [
        module for module in modules if re.match("s[0-9]+_c[0-9]+_*", module)
    ]
    return challenge_modules


def _get_package_modules():
    with importlib.resources.path(__package__, "") as package_dir:
        files = os.listdir(package_dir)
        module_files = [file_ for file_ in files if Path(file_).suffix == ".py"]
        modules = [str(Path(module_file).stem) for module_file in module_files]
        return modules
