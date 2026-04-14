"""
refresh_dummyjson_tokens.py
---------------------------
Fetches fresh JWT tokens from dummyjson.com for three test users
and writes them to sample_specs/dummyjson_tokens.json.

Run this before scanning dummyjson — tokens expire after 60 minutes.

Usage:
    python scripts/refresh_dummyjson_tokens.py
"""

import json
import os
import sys
import requests

USERS = [
    {"name": "emilys",   "password": "emilyspass",   "user_id": 1},
    {"name": "michaelw", "password": "michaelwpass",  "user_id": 2},
    {"name": "sophiab",  "password": "sophiabpass",   "user_id": 3},
]

LOGIN_URL     = "https://dummyjson.com/auth/login"
OUTPUT_FILE   = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "dummyjson_tokens.json")


def fetch_token(username: str, password: str) -> str:
    resp = requests.post(
        LOGIN_URL,
        json={"username": username, "password": password, "expiresInMins": 60},
        timeout=10,
    )
    resp.raise_for_status()
    return resp.json()["accessToken"]


def main():
    print("Fetching fresh tokens from dummyjson.com...")
    tokens = []

    for user in USERS:
        try:
            token = fetch_token(user["name"], user["password"])
            tokens.append({
                "name":    user["name"],
                "token":   token,
                "user_id": user["user_id"],
            })
            print(f"  OK  {user['name']} (id={user['user_id']})")
        except Exception as e:
            print(f"  FAIL  {user['name']}: {e}", file=sys.stderr)
            sys.exit(1)

    out = os.path.abspath(OUTPUT_FILE)
    with open(out, "w", encoding='utf-8') as f:
        json.dump(tokens, f, indent=2)

    print(f"\nTokens saved to: {out}")
    print("Valid for 60 minutes. Run scan now:\n")
    print("  python cli.py --spec sample_specs/dummyjson.yaml "
          "--tokens sample_specs/dummyjson_tokens.json "
          "--skip ssrf --delay 0.5 --ids 1,2,3,4,5")


if __name__ == "__main__":
    main()
