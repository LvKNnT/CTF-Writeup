#!/usr/bin/env sage
"""Compatibility entry point for the Baby Circuit remote solver."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from baby_circuit_solver import main


if __name__ == "__main__":
    main()
