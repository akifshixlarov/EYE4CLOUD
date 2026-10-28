"""
scripts/hash_password.py

Creates a bcrypt hash for the dashboard password. Copy the result into .env:

    DASHBOARD_PASSWORD_HASH=<resulting hash>

Usage:
    python scripts/hash_password.py           # prompts for the password (hidden input)
    echo "password" | python scripts/hash_password.py

Why a hash: a plain password (DASHBOARD_PASSWORD) also works, but then
streamlit-authenticator re-hashes it on every rerun (bcrypt is deliberately
slow) - the hash version is both faster and keeps no plain password in .env.
"""

import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit_authenticator as stauth  # noqa: E402


def main() -> int:
    if sys.stdin.isatty():
        password = getpass.getpass("Password: ")
    else:
        password = sys.stdin.readline().strip()

    if not password:
        print("Password cannot be empty.", file=sys.stderr)
        return 1

    print(stauth.Hasher.hash(password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
