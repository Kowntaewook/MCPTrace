"""Check package and Volatility adapters agree on the semantic version."""

import re
from pathlib import Path

from mcptrace import __version__

ROOT = Path(__file__).resolve().parents[1]


def test_package_metadata_and_plugin_versions_match():
    metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    package = re.search(r'(?m)^version = "([^"]+)"$', metadata)
    assert package is not None and package.group(1) == __version__

    release_tuple = tuple(int(part) for part in __version__.split("."))
    assert len(release_tuple) == 3
    for target in ("windows", "linux"):
        source = (ROOT / "plugins" / target / "mcptrace.py").read_text(encoding="utf-8")
        match = re.search(r"(?m)^    _version = \((\d+), (\d+), (\d+)\)$", source)
        assert match is not None
        assert tuple(int(value) for value in match.groups()) == release_tuple
