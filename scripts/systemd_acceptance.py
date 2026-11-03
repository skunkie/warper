#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 skunkie
#
# SPDX-License-Identifier: MIT

"""Installed-unit acceptance, exclusively in a disposable GitHub-hosted VM."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time


UNIT = Path('/etc/systemd/system/warper.service')
CLIENT = Path('/usr/local/bin/warper')
DAEMON = Path('/usr/local/bin/warperd')
STATE = (Path('/run/warper'), Path('/var/lib/warper'), Path('/etc/warper'))


def require_disposable(environment, uid, acknowledged):
    if not (acknowledged and uid == 0
            and environment.get('GITHUB_ACTIONS') == 'true'
            and environment.get('RUNNER_ENVIRONMENT') == 'github-hosted'):
        raise ValueError('requires root and explicit disposable GitHub-hosted VM acknowledgement')


def identity(path):
    stat = path.lstat()
    return (stat.st_dev, stat.st_ino, stat.st_mode, stat.st_uid, stat.st_gid,
            hashlib.sha256(path.read_bytes()).hexdigest())


def exercise(args, environment):
    require_disposable(environment, os.geteuid(), args.disposable_github_vm)
    if any(path.exists() or path.is_symlink() for path in (UNIT, CLIENT, DAEMON, *STATE)):
        raise ValueError('existing installation or state must not be overwritten')
    evidence = args.evidence.resolve()
    evidence.mkdir(parents=True, exist_ok=True)
    installed = {}
    log = []
    errors = []
    resolver = identity(Path('/etc/resolv.conf'))
    lock = None

    def run(arguments, *, check=True, seconds=55):
        result = subprocess.run([str(value) for value in arguments], check=False,
                                capture_output=True, text=True, timeout=seconds)
        log.append({'arguments': [str(value) for value in arguments],
                    'code': result.returncode, 'stdout': result.stdout,
                    'stderr': result.stderr})
        if check and result.returncode != 0:
            raise RuntimeError(f'command failed: {arguments[0]} (exit {result.returncode})')
        return result

    def control(owner=False):
        command = [CLIENT, 'status', '--json']
        if owner:
            command = ['/usr/bin/setpriv', '--reuid', str(args.owner_uid),
                       '--regid', str(args.owner_gid), '--init-groups', '--', *command]
        result = run(command, check=False, seconds=8)
        if result.returncode != 0:
            return None
        status = json.loads(result.stdout)
        if status['state'] != 'disconnected' or status['configuration_present']:
            raise RuntimeError('installed idle unit reported unexpected network state')
        return status

    def ready(owner=False, previous_pid=None):
        deadline = time.monotonic() + 35
        while time.monotonic() < deadline:
            pid = int(run(['systemctl', 'show', '--property=MainPID', '--value',
                           'warper.service']).stdout.strip())
            if pid and pid != previous_pid and control(owner) is not None:
                return pid
            time.sleep(0.1)
        raise TimeoutError('installed unit did not become control-ready')

    try:
        existing = run(['systemctl', 'show', '--property=LoadState', '--value',
                        'warper.service'], check=False)
        if existing.stdout.strip() != 'not-found':
            raise ValueError('a foreign service unit already exists')
        for source, destination, mode in (
                (args.warper, CLIENT, 0o755), (args.warperd, DAEMON, 0o755),
                (args.unit, UNIT, 0o644)):
            # Exclusive creation preserves an installation raced into this VM.
            with Path(source).open('rb') as sample, destination.open('xb') as output:
                shutil.copyfileobj(sample, output)
                os.fchmod(output.fileno(), mode)
            installed[destination] = identity(destination)
        run(['systemd-analyze', 'verify', '--man=no', UNIT])
        run(['systemctl', 'daemon-reload'])
        run(['systemctl', 'enable', '--now', 'warper.service'])
        first = ready()
        lock = Path('/run/warper/service.lock').stat().st_ino
        run([CLIENT, 'owner', 'enroll', '--uid', str(args.owner_uid)])
        ready(owner=True)
        run(['systemctl', 'restart', 'warper.service'])
        second = ready(owner=True, previous_pid=first)
        run(['systemctl', 'kill', '--kill-whom=main', '--signal=SIGKILL', 'warper.service'])
        ready(owner=True, previous_pid=second)
        run(['systemctl', 'stop', 'warper.service'])
        if Path('/run/warper/control.sock').exists():
            raise RuntimeError('systemd stop left the control endpoint published')
        if Path('/run/warper/service.lock').stat().st_ino != lock:
            raise RuntimeError('systemd removed or replaced the persistent lock inode')
        # These deliberate rapid lifecycle transitions exhaust the unit's
        # three-start budget. Explicit administrative reset permits this start.
        run(['systemctl', 'reset-failed', 'warper.service'])
        run(['systemctl', 'start', 'warper.service'])
        ready(owner=True)
        print('PASS installed unit start, owner access, restart, SIGKILL recovery and stop')
    except Exception as error:  # Preserve the initial failure alongside independent cleanup.
        errors.append(f'{type(error).__name__}: {error}')
    finally:
        if UNIT in installed:
            try:
                run(['journalctl', '--unit=warper.service', '--no-pager', '--lines=100'], check=False)
                stopped = run(['systemctl', 'disable', '--now', 'warper.service'], check=False)
                if stopped.returncode != 0:
                    run(['systemctl', 'kill', '--kill-whom=all', '--signal=SIGKILL',
                         'warper.service'], check=False)
                    raise RuntimeError('unit cleanup required forced termination')
                if Path('/run/warper/control.sock').exists():
                    raise RuntimeError('cleanup left the control endpoint published')
            except Exception as error:
                errors.append(f'cleanup: {type(error).__name__}: {error}')
        for path, original in reversed(list(installed.items())):
            try:
                if identity(path) != original:
                    raise RuntimeError('installed object changed; preserving it')
                path.unlink()
            except Exception as error:
                errors.append(f'cleanup: {path.name}: {type(error).__name__}: {error}')
        if UNIT in installed:
            try:
                run(['systemctl', 'daemon-reload'])
            except Exception as error:
                errors.append(f'cleanup: {type(error).__name__}: {error}')
        try:
            if identity(Path('/etc/resolv.conf')) != resolver:
                raise RuntimeError('resolver identity or bytes changed')
            if lock is not None and Path('/run/warper/service.lock').stat().st_ino != lock:
                raise RuntimeError('persistent lock inode changed')
        except Exception as error:
            errors.append(f'preservation: {type(error).__name__}: {error}')
        (evidence / 'commands.json').write_text(json.dumps(log, indent=2) + '\n')
        (evidence / 'result.json').write_text(json.dumps({
            'revision': args.revision, 'disposable_vm': 'github-hosted',
            'errors': errors, 'code': int(bool(errors)),
            'binaries': {path.name: stamp[-1] for path, stamp in installed.items()},
            'scope': 'installed idle service; no configuration, routes or DNS mutation',
        }, indent=2) + '\n')
    if errors:
        raise RuntimeError('; '.join(errors))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disposable-github-vm', action='store_true')
    parser.add_argument('--warper', type=Path, required=True)
    parser.add_argument('--warperd', type=Path, required=True)
    parser.add_argument('--unit', type=Path, required=True)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--revision', required=True)
    parser.add_argument('--owner-uid', type=int, required=True)
    parser.add_argument('--owner-gid', type=int, required=True)
    args = parser.parse_args()
    if not 0 < args.owner_uid < 2**32 - 1 or not 0 < args.owner_gid < 2**32 - 1:
        parser.error('owner must be an ordinary nonreserved UID/GID')
    try:
        exercise(args, os.environ)
    except (ValueError, RuntimeError) as error:
        parser.exit(1, f'{error}\n')


if __name__ == '__main__':
    main()
