# pylint: disable=no-self-use, unused-argument, redefined-outer-name
import re
import logging
import subprocess
from pathlib import Path

import pytest

import drvn.cryptography.utils as utils


@pytest.fixture(scope="class")
def workspace():
    workspace_path = _set_up_workspace()
    yield workspace_path
    _tear_down_workspace()


class TestScript:
    def test_help_exits_with_returncode_zero(self):
        utils.try_cmd("drvn_cryptography_run_cryptopals_challenge --help")

    def test_cli_call_to_a_challenge_work(self):
        utils.try_cmd("drvn_cryptography_run_cryptopals_challenge 1")
        utils.try_cmd("drvn_cryptography_run_cryptopals_challenge 2")
        utils.try_cmd("drvn_cryptography_run_cryptopals_challenge 3")


def _set_up_workspace():
    workspace_path = _get_workspace_path()
    logging.debug("Setting up integration test workspace ...")
    utils.try_cmd(f"mkdir -p {workspace_path}")
    return workspace_path


def _tear_down_workspace():
    workspace_path = _get_workspace_path()
    logging.debug("Tearing down integration test workspace ...")
    utils.try_cmd(f"rm -rf {workspace_path}")


def _get_workspace_path():
    workspace_path = Path("/tmp/drvn_cryptography/integration_workspace")
    return workspace_path
