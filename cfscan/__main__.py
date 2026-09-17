"""Allow ``python3 -m cfscan`` to behave exactly like the cfscan command."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
