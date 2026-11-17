from __future__ import annotations

import argparse
import sys
from importlib.metadata import entry_points
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from vbeye.engine import ScanReport

ENTRY_POINT_GROUP = "vbeye.plugins"


class PluginError(Exception):
    pass


@runtime_checkable
class OutputPlugin(Protocol):
    name: str

    def add_arguments(self, parser: argparse.ArgumentParser) -> None: ...

    def enabled(self, args: argparse.Namespace) -> bool: ...

    def prepare(self, args: argparse.Namespace) -> None: ...

    def write(
        self,
        report: ScanReport,
        args: argparse.Namespace,
        output_dir: Path,
        stem: str,
    ) -> Path | None: ...


def load_plugins() -> list[OutputPlugin]:
    plugins: list[OutputPlugin] = []
    for ep in entry_points(group=ENTRY_POINT_GROUP):
        try:
            obj = ep.load()
            plugin = obj() if isinstance(obj, type) else obj
        except Exception as e:
            print(f"vbeye: failed to load plugin '{ep.name}': {e}", file=sys.stderr)
            continue
        if isinstance(plugin, OutputPlugin):
            plugins.append(plugin)
        else:
            print(f"vbeye: plugin '{ep.name}' does not implement OutputPlugin", file=sys.stderr)
    return plugins
