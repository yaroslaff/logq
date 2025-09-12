import toml
import os
from typing import List, Dict, Any

DEFAULT_PATHS = [
    "/etc/logq.toml",
    "/usr/local/etc/logq.toml",
    os.path.expanduser("~/.logq.toml"),
    "logq.toml"
]


class Settings:
    def_regex: str | None
    logs: dict

    def __repr__(self):
        return f"Settings(def_regex={self.def_regex})"

    def getlogconf(self, path) -> Dict[str, Any]:
        for v in self.logs.values():
            if v['path'] == path:
                return v
        # not found
        return dict(regex = self.def_regex)

settings = Settings()

def load_config(path=None):
    """Загрузить конфиг из указанного пути или из стандартных путей"""
    paths = [path] if path else DEFAULT_PATHS
    for p in paths:
        if os.path.exists(p):
            print(f"Loading config from {p}")

            tomlconf =  toml.load(p)

            # init settings
            settings.def_regex = tomlconf.get("def_regex", None)
            settings.logs = tomlconf.get("log", {})
            
    return {}  
