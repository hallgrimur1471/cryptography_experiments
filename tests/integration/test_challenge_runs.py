# pylint: disable=no-self-use, unused-argument, redefined-outer-name
import re
import logging
import subprocess
from pathlib import Path

import pytest

import drvn.cryptography.utils as utils
import drvn.cryptography_challenges.challenges as challenges


@pytest.fixture(scope="class")
def workspace():
    workspace_path = _set_up_workspace()
    yield workspace_path
    _tear_down_workspace()


class TestChallenges:
    def test_all_challenges_finish_without_raising_an_exception(
        self, workspace
    ):
        current_challenge = 1
        while True:
            try:
                challenges.run(current_challenge)
            except ValueError as e:
                if re.search("Challenge [0-9]+ does not exist", str(e)):
                    break
                raise

            current_challenge += 1


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
