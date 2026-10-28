"""Coordinate F1 signing without reading any trustee's private configuration."""
from pathlib import Path
import argparse
import json
import os
import shlex
import subprocess
import sys
import threading
import time

p = argparse.ArgumentParser()
for flag in ('tools', 'state', 'checker', 'pczt', 'approval', 'run'):
    p.add_argument('--' + flag, type=Path, required=True)
p.add_argument('--single', action='store_true')
a = p.parse_args()
os.umask(0o077)
a.run.mkdir(mode=0o700, exist_ok=False)
os.environ['SSL_CERT_FILE'] = str(a.state / 'relay-ca.crt')
group = (a.state / 'group.txt').read_text().strip()

def run(args, **kwargs):
    args = list(map(str, args))
    print('COMMAND', shlex.join(args), flush=True)
    return subprocess.run(args, check=True, **kwargs)

def close_sessions():
    # This relay/group is dedicated to this test. A deliberate threshold failure
    # leaves an unfinished session, which must not contaminate a later run.
    run([a.tools / 'frost-client', 'sessions', '--config', a.state / 'coordinator.toml',
         '--group', group, '--close-all'])

close_sessions()
run([a.checker, 'fund-check', a.pczt, a.approval, a.state / 'fund.fvk', a.run])
signers = [1] if a.single else [1, 2]
pubkeys = [json.loads((a.state / f'public{n}.json').read_text())['communication_public_key'] for n in signers]
coordinator = [str(a.tools / 'frost-client'), 'coordinator', '--config', str(a.state / 'coordinator.toml'),
               '--group', group, '--signers', ','.join(pubkeys), '--message', str(a.run / 'sighash.bin'),
               '--randomizer', str(a.run / 'alpha.bin'), '--signature', str(a.run / 'signature.bin')]
children = []
threads = []
observed = {}
def start(args, label):
    print('COMMAND', shlex.join(args), flush=True)
    child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    children.append(child)
    print(f'{label}_PROCESS pid={child.pid}', flush=True)
    observed[label] = []
    def stream():
        for line in child.stdout:
            observed[label].append(line)
            print(f'{label} {line}', end='', flush=True)
    thread = threading.Thread(target=stream)
    thread.start()
    threads.append(thread)
    return child

try:
    coord = start(coordinator, 'COORDINATOR')
    time.sleep(3)
    trustees = []
    for n in signers:
        args = [sys.executable, 'f1/guard.py', '--checker', str(a.checker), '--pczt', str(a.pczt),
                '--approval', str(a.approval), '--fvk', str(a.state / 'fund.fvk'),
                '--checked', str(a.run / f'checked{n}'), '--client', str(a.tools / 'frost-client'),
                '--config', str(a.state / f'trustee{n}/config.toml'), '--group', group]
        trustees.append(start(args, f'TRUSTEE{n}'))
    statuses = [child.wait(timeout=180) for child in trustees]
    print('TRUSTEE_EXIT_STATUS', statuses, flush=True)
    if a.single:
        for thread in threads[1:]:
            thread.join(timeout=10)
        assert statuses[0] != 0, 'STOP: single trustee unexpectedly signed'
        assert any('Error: IncorrectNumberOfCommitments' in line for line in observed['TRUSTEE1']), 'Negative control inconclusive: no threshold rejection'
        assert not (a.run / 'signature.bin').exists(), 'STOP: single-trustee signature produced'
        print('SINGLE_TRUSTEE no_valid_transaction no_aggregate_signature', flush=True)
    else:
        assert statuses == [0, 0], 'F1 two-trustee signing failed'
        assert coord.wait(timeout=60) == 0, 'F1 aggregation failed'
        signature = (a.run / 'signature.bin').read_bytes()
        assert len(signature) == 64
        print('PUBLIC_SIGNATURE_INPUT', signature.hex(), flush=True)
        run([a.tools / 'zcash-sign', 'sign', '--network', 'test', '--tx-plan', a.pczt,
             '--tx', a.run / 'signed.pczt'], input=signature.hex() + '\n', text=True)
        run([a.checker, 'fund-extract', a.run / 'signed.pczt', a.run / 'payout.raw'])
finally:
    for child in children:
        if child.poll() is None:
            print(f'TERMINATE own ceremony child pid={child.pid}', flush=True)
            child.terminate()
            child.wait(timeout=10)
    for thread in threads:
        thread.join(timeout=10)
    close_sessions()
