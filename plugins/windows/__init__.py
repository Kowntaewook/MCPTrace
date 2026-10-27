"""Extend the Windows plugin namespace without hiding built-in plugins."""

from pkgutil import extend_path

__path__ = extend_path(__path__, __name__)
