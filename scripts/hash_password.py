"""
scripts/hash_password.py

Dashboard parolu ucun bcrypt hash yaradir. Neticeni .env-e kopyala:

    DASHBOARD_PASSWORD_HASH=<cixan hash>

Istifade:
    python scripts/hash_password.py           # parol soruslur (ekranda gorunmur)
    echo "parol" | python scripts/hash_password.py

Niye hash: aciq parol (DASHBOARD_PASSWORD) da isleyir, amma o halda
streamlit-authenticator her rerun-da yeniden hash hesablayir (bcrypt qesden
yavasdir) - hash versiyasi hem daha suretli, hem de .env-de aciq parol saxlamir.
"""

import getpass
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import streamlit_authenticator as stauth  # noqa: E402


def main() -> int:
    if sys.stdin.isatty():
        password = getpass.getpass("Parol: ")
    else:
        password = sys.stdin.readline().strip()

    if not password:
        print("Parol bos ola bilmez.", file=sys.stderr)
        return 1

    print(stauth.Hasher.hash(password))
    return 0


if __name__ == "__main__":
    sys.exit(main())
