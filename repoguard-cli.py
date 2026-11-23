"""Run repoguard without installing it: `py path\\to\\repoguard-cli.py scan <target>`.

Runs with the project folder on sys.path, never the current directory (so a scanned folder can't shadow modules).
"""

import sys
from pathlib import Path

HERE = str(Path(__file__).resolve().parent)
sys.path[:] = [HERE] + [p for p in sys.path if p not in ("", ".", HERE)]

from repoguard.cli import main  # noqa: E402

raise SystemExit(main())
