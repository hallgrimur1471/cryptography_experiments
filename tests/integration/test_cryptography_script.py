# pylint: disable=no-self-use, unused-argument, redefined-outer-name
import logging
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

    def test_all_challenges_exit_with_returncode_zero(self, workspace):
        num_challenges = 9

        for challenge_num in range(1, num_challenges + 1):
            # assert returncode zero
            utils.try_cmd(
                f"drvn_cryptography_run_cryptopals_challenge {challenge_num}",
                cwd=workspace,
            )


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
