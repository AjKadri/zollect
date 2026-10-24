"""One trustee's approval boundary before frost-client can emit a signature share.

The checker validates the actual PCZT against the approval. The wrapper then
compares the coordinator's requested message with that PCZT's computed sighash.
It never opens the trustee config itself. frost-client loads only that share.
"""
import argparse
from pathlib import Path
import shlex
import subprocess
import sys

p = argparse.ArgumentParser()
for flag in ('checker', 'pczt', 'approval', 'fvk', 'checked', 'client', 'config', 'group'):
    p.add_argument('--' + flag, required=True)
a = p.parse_args()
command = [a.checker, 'fund-check', a.pczt, a.approval, a.fvk, a.checked]
print('COMMAND', shlex.join(command), flush=True)
checked = subprocess.run(command)
if checked.returncode:
    print('REFUSED before nonce generation or signature share: PCZT violates approval', flush=True)
    sys.exit(20)
expected = (Path(a.checked) / 'sighash.bin').read_bytes().hex()
command = [a.client, 'participant', '--config', a.config, '--group', a.group]
print('COMMAND', shlex.join(command), flush=True)
child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, bufsize=1)
print('TRUSTEE_PROCESS pid=' + str(child.pid), flush=True)
message_next = False
matched = False
for line in child.stdout:
    print(line, end='', flush=True)
    if message_next:
        matched = line.strip() == expected
        message_next = False
    if line.startswith('Message to be signed (hex-encoded):'):
        message_next = True
    if 'Do you want to sign it?' in line:
        child.stdin.write('y\n' if matched else 'n\n')
        child.stdin.flush()
        print('MESSAGE_CHECK ' + ('MATCH' if matched else 'REFUSED'), flush=True)
status = child.wait()
sys.exit(status if status else (0 if matched else 21))
