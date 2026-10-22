#!/usr/bin/python3
"""Candidate-side forced command for a new portal-specific SSH public key."""
import os
import re
import sys

NODES = ('amd103', 'cix106', 'intel108')
if len(sys.argv) != 2 or sys.argv[1] not in NODES:
    sys.exit(1)
node = sys.argv[1]
parts = os.environ.get('SSH_ORIGINAL_COMMAND', '').split(' ')
prefix = ['/usr/bin/python3', '/opt/secdns-persistent-20261021/candidate_status.py']
if len(parts) not in (4, 5) or parts[:2] != prefix or parts[3] != node:
    sys.exit(1)
action = parts[2]
if action in ('status', 'bgp-get', 'bgp-validate','health-get','health-validate'):
    if len(parts) != 4:
        sys.exit(1)
elif action in ('drain', 'resume', 'bgp-apply','health-apply'):
    if len(parts) != 5 or not re.fullmatch(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', parts[4]):
        sys.exit(1)
else:
    sys.exit(1)
os.execv('/usr/bin/python3', parts)
