#!/usr/bin/env python3

"""Runs the given command, retrying it after 1, 2 and 4 minutes if it fails,
e.g. for network operations against servers that are sometimes unreachable.

Every attempt, including the first one, is preceded by an extra random delay of
up to 30 seconds, so that jobs that start at the same time do not all hit the
server at once (nor retry at once).

The command must be safe to run again after a failure (e.g. `git clone` removes
the directory it created when it fails).
"""

import random
import shlex
import subprocess
import sys
import time

DELAYS = (0, 60, 120, 240)
MAX_JITTER = 30

def log(message):
    print(f"retry.py: {message}", file=sys.stderr, flush=True)

def main():
    command = sys.argv[1:]
    if not command:
        sys.exit("usage: retry.py COMMAND [ARGUMENT...]")

    for attempt, delay in enumerate(DELAYS, start=1):
        delay += random.uniform(0, MAX_JITTER)
        log(f"attempt {attempt} of {len(DELAYS)} in {delay:.0f} seconds: {shlex.join(command)}")
        time.sleep(delay)

        code = subprocess.run(command).returncode
        if code == 0:
            return

        log(f"attempt {attempt} of {len(DELAYS)} failed (exit code {code})")

    sys.exit(code if code > 0 else 1)

if __name__ == "__main__":
    main()
