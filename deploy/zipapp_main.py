"""Zipapp entry dispatcher: service modes first, CLI otherwise."""
from __future__ import annotations

import os
import sys


def dispatch(argv):
    if argv == ["--down"]:
        from minirj.service import main
        return main(["--down"])
    if len(argv) == 1 and argv[0] == os.environ.get("MINIRJ_INTERFACE"):
        from minirj.service import main
        return main(argv)
    if not argv:
        from minirj.service import main
        return main([])
    from minirj.main import main
    return main(argv)


if __name__ == "__main__":
    sys.exit(dispatch(sys.argv[1:]))
