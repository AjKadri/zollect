"""Invoke upstream zcash-sign generation, keeping the fund viewing key local."""
from pathlib import Path
import os
import shlex
import subprocess
import sys

os.umask(0o077)
tools, state, checker = map(Path, sys.argv[1:4])
group = (state / 'group.txt').read_text().strip()
args = [str(tools / 'zcash-sign'), 'generate', '--ak', group, '--network', 'test']
print('COMMAND', shlex.join(args), flush=True)
with (state / 'generated-viewing-key.txt').open('w') as out:
    result = subprocess.run(args, stdout=out, check=True)
print('OUTPUT saved privately: generated-viewing-key.txt (contains fund viewing key)', flush=True)
args = [str(checker), 'fund-import', str(state / 'generated-viewing-key.txt'),
        str(state / 'fund.fvk'), str(state / 'fund-address.txt')]
print('COMMAND', shlex.join(args), flush=True)
subprocess.run(args, check=True)
