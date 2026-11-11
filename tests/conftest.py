from pathlib import Path
import shutil
import sys

import pytest

# Tests import component sources; bytecode caches inside declared build
# contexts are rejected by the planner, so never write them during tests.
sys.dont_write_bytecode = True

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checkout(tmp_path):
    for directory in ("components/platform", "presets", "tests/fixtures/modules/echo"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    return tmp_path
