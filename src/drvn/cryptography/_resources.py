import logging
import importlib.resources

import svarmi.create_package._utils as utils


def get_contents(resource_relative_path):
    with importlib.resources.path(__package__, "data") as data_dir:
        resource_file_path = data_dir / resource_relative_path
        logging.debug(f"Reading resource file {resource_file_path} ...")
        with open(data_dir / resource_relative_path, "r") as resource_file:
            resource_file_contents = resource_file.read()
    return resource_file_contents


def copy(resource_relative_path, destination_path):
    with importlib.resources.path(__package__, "data") as data_dir:
        resource_file_path = data_dir / resource_relative_path
        utils.try_cmd(f"cp -r {resource_file_path} {destination_path}")
