from pathlib import Path
import shutil

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def checkout(tmp_path):
    for directory in ("components/platform", "presets", "tests/fixtures/modules/echo"):
        shutil.copytree(ROOT / directory, tmp_path / directory)
    return tmp_path
