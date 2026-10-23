"""Run only as systemd MainPID with KillMode=control-group; never daemonize."""
import json
import os
import pathlib
import selectors
import signal
import subprocess
import sys
import time


class Heartbeat:
    def __init__(self, now):
        self.last_progress = now
        self.sequence = 0

    def accept(self, line, now):
        obj = json.loads(line)
        seq, observed = obj['sequence'], obj['observed_monotonic']
        if obj['type'] != 'health' or type(seq) is not int or seq <= self.sequence:
            raise ValueError('nonadvancing heartbeat')
        if type(observed) not in (int, float) or not 0 <= now - observed <= 12:
            raise ValueError('stale heartbeat')
        for field in ('healthy', 'advertised'):
            if not isinstance(obj[field], list) or len(obj[field]) != 4 or any(type(x) is not bool for x in obj[field]):
                raise ValueError('invalid health states')
        self.sequence, self.last_progress = seq, now

    def check(self, now):
        if now - self.last_progress > 12:
            raise RuntimeError('checker heartbeat expired')


def stop(children):
    # Close route producer first; only our direct foreground children are touched.
    for name in ('bgpd', 'zebra', 'checker'):
        p = children.get(name)
        if p is None or p.poll() is not None:
            continue
        p.terminate()
        try:
            p.wait(timeout=2)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait(timeout=2)


def bgp_identity(config):
    """Require the configured BGP instance and both service address families."""
    lines = {line.strip() for line in config.splitlines()}
    routers = {line for line in lines if line.startswith('router bgp ')}
    ids = {line for line in lines if line.startswith('bgp router-id ')}
    afis = {'address-family ipv4 unicast', 'address-family ipv6 unicast'}
    if len(routers) != 1 or len(ids) != 1 or not afis <= lines:
        raise ValueError('expected one configured BGP instance with both service families')
    return routers | ids | afis


def wait_bgp_ready(state, expected, children, deadline):
    # A VTY socket appears before bgpd finishes loading its configuration.
    # Never launch the route-changing checker against that intermediate state.
    while True:
        if any(child.poll() is not None for child in children.values()):
            raise RuntimeError('owned child exited during BGP startup')
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError('bgpd configuration not ready before startup deadline')
        try:
            result = subprocess.run(
                ['vtysh', '--vty_socket', str(state), '-d', 'bgpd',
                 '-c', 'show running-config'],
                capture_output=True, text=True, timeout=min(.5, remaining), check=False)
            lines = {line.strip() for line in result.stdout.splitlines()}
            if (result.returncode == 0 and not result.stderr.strip()
                    and '%' not in result.stdout and expected <= lines
                    and time.monotonic() < deadline
                    and all(child.poll() is None for child in children.values())):
                return
        except subprocess.TimeoutExpired:
            pass
        time.sleep(min(.05, max(0, deadline - time.monotonic())))


def main(base):
    base = pathlib.Path(base).resolve(strict=True)
    state = base / 'state'
    if not state.is_dir():
        raise RuntimeError('precreated owned state directory required')
    expected = bgp_identity((base / 'bgp.conf').read_text())
    children = {}
    try:
        for name, cfg in (('zebra', 'zebra.conf'), ('bgpd', 'bgp.conf')):
            args = ['/usr/lib/frr/' + name, '-f', str(base / cfg), '-i', str(state / (name + '.pid')), '-z', str(state / 'zserv.api'), '--vty_socket', str(state), '-P', '0', '-u', 'frr', '-g', 'frr']
            if name == 'bgpd':
                args += ['-p', '1179']
            children[name] = subprocess.Popen(args, stdin=subprocess.DEVNULL)
            deadline = time.monotonic() + 4
            while not (state / (name + '.vty')).exists():
                if children[name].poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError(name + ' startup failed')
                time.sleep(.05)
            if name == 'bgpd':
                wait_bgp_ready(state, expected, children, deadline)
        children['checker'] = subprocess.Popen([sys.executable, '-u', str(base / 'health_controller.py'), str(base / 'health.json')], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE)
        pipe = children['checker'].stdout
        os.set_blocking(pipe.fileno(), False)
        heartbeat = Heartbeat(time.monotonic())
        pending = b''
        with selectors.DefaultSelector() as selector:
            selector.register(pipe, selectors.EVENT_READ)
            while True:
                if any(p.poll() is not None for p in children.values()):
                    raise RuntimeError('owned child exited')
                heartbeat.check(time.monotonic())
                for _, _ in selector.select(timeout=.25):
                    chunk = os.read(pipe.fileno(), 8192)
                    if not chunk:
                        raise RuntimeError('checker pipe closed')
                    pending += chunk
                    if len(pending) > 32768:
                        raise RuntimeError('oversized heartbeat')
                    while b'\n' in pending:
                        line, pending = pending.split(b'\n', 1)
                        heartbeat.accept(line, time.monotonic())
                        print(line.decode(), flush=True)
    finally:
        stop(children)


if __name__ == '__main__':
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *_: sys.exit(0))
    main(sys.argv[1])
