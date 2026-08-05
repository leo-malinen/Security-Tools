import os

import yaml

DEFAULT_PATH = os.environ.get("NETMON_CONFIG", "config.yaml")


class Config:
    def __init__(self, data):
        self._data = data or {}

    def get(self, path, default=None):
        node = self._data
        for part in path.split("."):
            if not isinstance(node, dict) or part not in node:
                return default
            node = node[part]
        return node

    @property
    def raw(self):
        return self._data


def load_config(path=None):
    target = path or DEFAULT_PATH
    with open(target, "r", encoding="utf-8") as handle:
        return Config(yaml.safe_load(handle))
