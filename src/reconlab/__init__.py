"""Helpers for authorized penetration-testing lab organization."""

from importlib.metadata import PackageNotFoundError, version

try:
    __version__ = version("reconlab")
except PackageNotFoundError:  # running from a source tree without an install
    __version__ = "0.0.0+unknown"
