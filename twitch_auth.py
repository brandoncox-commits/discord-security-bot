"""
One-time Twitch OAuth helper for Bams Modmin Tools.
=================================================

Mints a *user* access token + refresh token for the bot's Twitch account so the
bot can read (and optionally post in) Twitch chat. Run this ONCE; paste the
printed values into `.env` on lab. twitchio refreshes the token automatically
afterwards using the client id/secret + refresh token.

What it does:
  1. Opens a Twitch login/consent page in your browser.
  2. You log in **as the bot's Twitch account** and approve the scopes.
  3. Twitch redirects to http://localhost:3000 with a one-time code, which this
     script catches on a tiny local web server.
  4. It exchanges that code for an access token + refresh token and prints them.

Prerequisites (see setup guide):
  - A Twitch application registered at https://dev.twitch.tv/console/apps with
    an OAuth Redirect URL of EXACTLY  http://localhost:3000
  - The Client ID and Client Secret from that app.

Usage:
  python twitch_auth.py --client-id <ID> --client-secret <SECRET>
  # or set TWITCH_CLIENT_ID / TWITCH_CLIENT_SECRET in the environment and just:
  python twitch_auth.py

Tip: run it in an incognito window's default browser, or use --force-verify
(on by default) so Twitch lets you pick the BOT account rather than silently
reusing your personal login.
"""

from __future__ import annotations

import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, HTTPServer

REDIRECT_URI = "http://localhost:3000"
REDIRECT_PORT = 3000
# chat:read  -> join channels and read chat messages (needed for XP + link codes)
# chat:edit  -> send messages in chat (optional: confirm "Linked!" in chat).
SCOPES = ["chat:read", "chat:edit"]

AUTH_URL = "https://id.twitch.tv/oauth2/authorize"
TOKEN_URL = "https://id.twitch.tv/oauth2/token"


class _CodeCatcher(BaseHTTPRequestHandler):
    """Single-shot handler that captures the ?code=... from the redirect."""

    code: str | None = None
    error: str | None = None

    def do_GET(self) -> None:  # noqa: N802 (http.server API)
        params = urllib.parse.parse_qs(urllib.parse.urlparse(self.path).query)
        if "code" in params:
            _CodeCatcher.code = params["code"][0]
            body = "<h2>Authorized.</h2>You can close this tab and return to the terminal."
        elif "error" in params:
            _CodeCatcher.error = params.get("error_description", params["error"])[0]
            body = f"<h2>Authorization failed.</h2>{_CodeCatcher.error}"
        else:
            # Stray request (e.g. favicon.ico, or a manual visit) — ignore it and
            # keep waiting for the real redirect rather than failing.
            self.send_response(204)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode("utf-8"))

    def log_message(self, *_args) -> None:  # silence the default request logging
        pass


def _wait_for_code() -> str:
    # Single-threaded: handle one request at a time on the main thread until we
    # see the real redirect. Stray requests (favicon, etc.) return 204 and the
    # loop simply continues. (Earlier this ran serve_forever in a thread AND
    # handle_request here, which raced for the socket and hung after the redirect.)
    server = HTTPServer(("localhost", REDIRECT_PORT), _CodeCatcher)
    print(f"Listening on {REDIRECT_URI} for the Twitch redirect…")
    try:
        while _CodeCatcher.code is None and _CodeCatcher.error is None:
            server.handle_request()
    finally:
        server.server_close()
    if _CodeCatcher.error:
        sys.exit(f"\n[!] Twitch returned an error: {_CodeCatcher.error}")
    return _CodeCatcher.code  # type: ignore[return-value]


def _exchange_code(client_id: str, client_secret: str, code: str) -> dict:
    data = urllib.parse.urlencode(
        {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": REDIRECT_URI,
        }
    ).encode()
    req = urllib.request.Request(TOKEN_URL, data=data, method="POST")
    import json

    try:
        with urllib.request.urlopen(req) as resp:  # noqa: S310 (trusted Twitch URL)
            return json.load(resp)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")
        sys.exit(
            f"\n[!] Token exchange failed (HTTP {exc.code}): {detail}\n"
            "    The most common cause is a reused/expired one-time code — "
            "just run the script again and complete the login in ONE go."
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="One-time Twitch bot token minter.")
    parser.add_argument("--client-id", default=os.getenv("TWITCH_CLIENT_ID"))
    parser.add_argument("--client-secret", default=os.getenv("TWITCH_CLIENT_SECRET"))
    parser.add_argument(
        "--force-verify",
        action="store_true",
        default=True,
        help="Force the Twitch login/consent screen (so you can pick the bot account).",
    )
    parser.add_argument(
        "--no-browser",
        action="store_true",
        help="Don't auto-open a browser; just print the URL to paste yourself "
        "(use this to open it in a private/incognito window as the bot account).",
    )
    args = parser.parse_args()

    if not args.client_id or not args.client_secret:
        sys.exit(
            "Missing credentials. Pass --client-id/--client-secret or set "
            "TWITCH_CLIENT_ID / TWITCH_CLIENT_SECRET in the environment."
        )

    query = urllib.parse.urlencode(
        {
            "client_id": args.client_id,
            "redirect_uri": REDIRECT_URI,
            "response_type": "code",
            "scope": " ".join(SCOPES),
            "force_verify": "true" if args.force_verify else "false",
        }
    )
    auth_url = f"{AUTH_URL}?{query}"

    print("\n" + "=" * 70)
    print("Open this URL in the browser window where you are logged in as the")
    print("BOT account, then click Authorize:")
    print("=" * 70)
    print(auth_url)
    print("=" * 70)
    if args.no_browser:
        print("(Not auto-opening — paste the URL above into your private window.)\n")
    else:
        print("Also attempting to auto-open your default browser. If that's the WRONG")
        print("account, ignore that tab and paste the URL above into a private window.\n")
        webbrowser.open(auth_url)

    code = _wait_for_code()
    tokens = _exchange_code(args.client_id, args.client_secret, code)

    access = tokens.get("access_token", "")
    refresh = tokens.get("refresh_token", "")
    scopes = " ".join(tokens.get("scope", []))

    print("\n" + "=" * 70)
    print("SUCCESS — add these lines to .env on lab:")
    print("=" * 70)
    print(f"TWITCH_BOT_ACCESS_TOKEN={access}")
    print(f"TWITCH_BOT_REFRESH_TOKEN={refresh}")
    print("=" * 70)
    print(f"(granted scopes: {scopes})")
    print("Keep these secret — they grant access to the bot's Twitch account.")


if __name__ == "__main__":
    main()
