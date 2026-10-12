"""
run_with_ngrok.py
------------------
Single entry point that starts ngrok AND app.py together, wires the
resulting public ngrok URL into PUBLIC_BASE_URL (see admin.py's
_public_url()) automatically, and shuts both down together on Ctrl+C.

Usage:
    python run_with_ngrok.py

Requirements:
    - ngrok installed and on your PATH (or set NGROK_PATH below to its
      full .exe/binary location), and `ngrok config add-authtoken ...`
      already run once.
    - requests installed (pip install requests) — only needed by this
      launcher script itself, not by the app.

What it does:
    1. Starts `ngrok http 5000` as a background process.
    2. Polls ngrok's local API (http://127.0.0.1:4040/api/tunnels) until
       the public https:// URL is assigned.
    3. Sets PUBLIC_BASE_URL to that URL and starts `python app.py` as a
       second background process, inheriting that environment variable.
    4. Streams both processes' output to this console.
    5. On Ctrl+C (or either process exiting), stops both cleanly.
"""

import os
import signal
import subprocess
import sys
import time

import requests

# If ngrok isn't on PATH, set the full path here instead, e.g.
# NGROK_PATH = r"C:\Users\hashi\ngrok\ngrok.exe"
NGROK_PATH = "ngrok"
FLASK_PORT = 5000
NGROK_API = "http://127.0.0.1:4040/api/tunnels"


def wait_for_ngrok_url(timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            resp = requests.get(NGROK_API, timeout=2)
            tunnels = resp.json().get("tunnels", [])
            for t in tunnels:
                if t.get("proto") == "https":
                    return t["public_url"]
        except requests.exceptions.RequestException:
            pass
        time.sleep(0.5)
    return None


def main():
    print(f"Starting ngrok (http {FLASK_PORT})...")
    ngrok_proc = subprocess.Popen(
        [NGROK_PATH, "http", str(FLASK_PORT)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    public_url = wait_for_ngrok_url()
    if not public_url:
        print("Could not get a public URL from ngrok within the timeout.")
        print("Check that ngrok is installed, on PATH (or NGROK_PATH is set),")
        print("and that you've run `ngrok config add-authtoken <token>` once.")
        ngrok_proc.terminate()
        sys.exit(1)

    print(f"ngrok public URL: {public_url}")
    print("Starting app.py with PUBLIC_BASE_URL set to that URL...\n")

    env = os.environ.copy()
    env["PUBLIC_BASE_URL"] = public_url

    flask_proc = subprocess.Popen([sys.executable, "app.py"], env=env)

    def shutdown(*_args):
        print("\nShutting down app.py and ngrok...")
        for proc in (flask_proc, ngrok_proc):
            if proc.poll() is None:
                proc.terminate()
        for proc in (flask_proc, ngrok_proc):
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, shutdown)

    # Wait on whichever process ends first (e.g. app.py crashing),
    # then tear the other one down too.
    while True:
        if flask_proc.poll() is not None:
            print("app.py exited.")
            shutdown()
        if ngrok_proc.poll() is not None:
            print("ngrok exited.")
            shutdown()
        time.sleep(1)


if __name__ == "__main__":
    main()
