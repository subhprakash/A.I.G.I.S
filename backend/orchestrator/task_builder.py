import yaml
from utils.yaml_loader import load_yaml


TOOLS_CONFIG = "config/tools.yaml"


def get_tools(language):

    config = load_yaml(TOOLS_CONFIG)

    return config["engines"].get(language, [])