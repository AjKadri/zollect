"""Export only public metadata from one trustee's frost-client configuration."""
import json
from pathlib import Path
import re
import sys
import tomllib

source, destination = map(Path, sys.argv[1:3])
text = source.read_text()
config = tomllib.loads(text)
groups = list(config.get('group', {}))
public = {'communication_public_key': config['communication_key']['pubkey'], 'groups': groups}
Path(destination).write_text(json.dumps(public))
if len(sys.argv) == 4:
    # The coordinator retains this trustee's communication identity, but no
    # private FROST key package. It never loads another trustee configuration.
    stripped, count = re.subn(r'^key_package = "[0-9a-f]*"$', 'key_package = ""', text, flags=re.M)
    assert count == 1 and groups
    assert all(not g['key_package'] for g in tomllib.loads(stripped)['group'].values())
    Path(sys.argv[3]).write_text(stripped)
print(f'PUBLIC_METADATA exported groups={len(groups)} private_key_packages_exported=0')
