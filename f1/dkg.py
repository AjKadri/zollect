"""Run three separate frost-client DKG processes through a local encrypted relay.

The parent reads public metadata only. Each client opens exactly its own config.
Private state stays outside the repository in the caller's protected directory.
"""
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
p.add_argument('--tools', type=Path, required=True)
p.add_argument('--state', type=Path, required=True)
p.add_argument('--resume-transport', action='store_true')
a = p.parse_args()
os.umask(0o077)
a.state.mkdir(mode=0o700, exist_ok=True)
client = str(a.tools / 'frost-client')

def command(args, **kwargs):
    print('COMMAND', shlex.join(map(str, args)), flush=True)
    return subprocess.run(list(map(str, args)), check=True, **kwargs)

if not a.resume_transport:
    for n in range(1, 4):
        folder = a.state / f'trustee{n}'
        folder.mkdir(mode=0o700, exist_ok=True)
        config = folder / 'config.toml'
        command([client, 'init', '--config', config])
        exported = command([client, 'export', '--name', f'trustee{n}', '--config', config], capture_output=True, text=True)
        print(exported.stdout + exported.stderr, end='', flush=True)
        contact = next(line for line in exported.stderr.splitlines() if line.startswith('zffrost1'))
        (a.state / f'contact{n}.txt').write_text(contact)
        command([sys.executable, 'f1/trustee_metadata.py', config, a.state / f'public{n}.json'])
        assert not json.loads((a.state / f'public{n}.json').read_text())['groups'], 'Existing DKG state must not be replaced'
    for n in range(1, 4):
        for other in range(1, 4):
            if other != n:
                contact = (a.state / f'contact{other}.txt').read_text().strip()
                command([client, 'import', contact, '--config', a.state / f'trustee{n}/config.toml'])

cert_config = a.state / 'certificate.cnf'
cert_config.write_text('[req]\ndistinguished_name=dn\nreq_extensions=ext\nprompt=no\n[dn]\nCN=localhost\n[ext]\nsubjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n')
if a.resume_transport:
    # The first certificate was a CA. Preserve and use it only as the local CA.
    old_pid = (a.state / 'relay.pid').read_text().strip()
    old = subprocess.run(['ps', '-p', old_pid, '-o', 'comm='], capture_output=True, text=True)
    print('COMMAND ps -p ' + old_pid + ' -o comm=', flush=True)
    print(old.stdout, end='', flush=True)
    if old.returncode == 0:
        assert old.stdout.strip() == str(a.tools / 'frostd')
        command(['kill', '-TERM', old_pid])
    command(['mv', a.state / 'relay.crt', a.state / 'relay-ca.crt'])
    command(['mv', a.state / 'relay.key', a.state / 'relay-ca.key'])
else:
    command(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '2',
             '-subj', '/CN=F1 local CA', '-addext', 'basicConstraints=critical,CA:TRUE',
             '-keyout', a.state / 'relay-ca.key', '-out', a.state / 'relay-ca.crt'])
command(['openssl', 'req', '-new', '-newkey', 'rsa:2048', '-nodes', '-config', cert_config,
         '-keyout', a.state / 'relay.key', '-out', a.state / 'relay.csr'])
command(['openssl', 'x509', '-req', '-in', a.state / 'relay.csr', '-CA', a.state / 'relay-ca.crt',
         '-CAkey', a.state / 'relay-ca.key', '-CAcreateserial', '-days', '2',
         '-extfile', cert_config, '-extensions', 'ext', '-out', a.state / 'relay.crt'])
relay_args = [str(a.tools / 'frostd'), '--ip', '127.0.0.1', '--port', '32144',
              '--tls-cert', str(a.state / 'relay.crt'), '--tls-key', str(a.state / 'relay.key')]
print('COMMAND', shlex.join(relay_args), flush=True)
relay_log = (a.state / 'relay.log').open('w')
relay = subprocess.Popen(relay_args, stdout=relay_log, stderr=subprocess.STDOUT)
(a.state / 'relay.pid').write_text(str(relay.pid))
print('RELAY_PROCESS pid=' + str(relay.pid), flush=True)
time.sleep(1)
assert relay.poll() is None, 'Relay did not start'
os.environ['SSL_CERT_FILE'] = str(a.state / 'relay-ca.crt')
pubkeys = [json.loads((a.state / f'public{n}.json').read_text())['communication_public_key'] for n in range(1, 4)]

threads = []
children = []
def stream(child, n):
    for line in child.stdout:
        print(f'TRUSTEE{n} {line}', end='', flush=True)

try:
    for n in range(1, 4):
        args = [client, 'dkg', '--config', str(a.state / f'trustee{n}/config.toml'),
                '--description', 'F1 regtest 2-of-3', '--server-url', 'localhost:32144',
                '--ciphersuite', 'redpallas', '--threshold', '2']
        if n == 1:
            args += ['--participants', ','.join(pubkeys)]
        print('COMMAND', shlex.join(args), flush=True)
        child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        children.append(child)
        print(f'TRUSTEE{n}_DKG_PROCESS pid={child.pid}', flush=True)
        thread = threading.Thread(target=stream, args=(child, n))
        thread.start()
        threads.append(thread)
        if n == 1:
            time.sleep(3)
    for child in children:
        assert child.wait(timeout=180) == 0, 'DKG failed'
    for thread in threads:
        thread.join()
    for n in range(1, 4):
        args = [sys.executable, 'f1/trustee_metadata.py', a.state / f'trustee{n}/config.toml', a.state / f'public{n}.json']
        if n == 3:
            args.append(a.state / 'coordinator.toml')
        command(args)
    groups = [json.loads((a.state / f'public{n}.json').read_text())['groups'] for n in range(1, 4)]
    assert all(len(g) == 1 and g == groups[0] for g in groups)
    (a.state / 'group.txt').write_text(groups[0][0])
    print(f'DKG_COMPLETE threshold=2 participants=3 matching_group_public_key={groups[0][0]}', flush=True)
    print('RELAY retained for signing; terminate this relay after F1', flush=True)
    relay.wait()
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    # Keep the relay for the following signing ceremony. It holds no key shares.
