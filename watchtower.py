#!/usr/bin/env python3
"""Compatibility entry point; the installed command is assetwatch."""

from assetwatch.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
