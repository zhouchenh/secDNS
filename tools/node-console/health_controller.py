"""Candidate namespace only. Supervisor MUST kill FRR on death/stale heartbeat."""
import ipaddress
import json
import os
import pathlib
import signal
import stat
import subprocess
import sys
import time
import threading
import health_settings

LABS = [ipaddress.ip_network(x) for x in ('192.0.2.0/24', '198.51.100.0/24', '203.0.113.0/24', '2001:db8::/32')]


def validate(c):
    if not 1 <= c['bgp_asn'] <= 4294967295:
        raise ValueError('ASN')
    for key in ('fixture', 'vty_socket'):
        if not pathlib.Path(c[key]).is_absolute():
            raise ValueError('absolute owned paths required')
    if 'query_helper' in c and not pathlib.Path(c['query_helper']).is_absolute():
        raise ValueError('absolute owned query helper required')
    entries = c['entries']
    if {(e['role'], e['family']) for e in entries} != {(r, f) for r in ('normal', 'dns64') for f in (4, 6)} or len(entries) != 4:
        raise ValueError('four independent role/family entries required')
    if sorted(c['allowed_prefixes']) != sorted(e['prefix'] for e in entries) or len(set(c['allowed_prefixes'])) != 4:
        raise ValueError('exact unique prefix allowlist required')
    for e in entries:
        p = ipaddress.ip_network(e['prefix'], strict=True)
        if p.version != e['family'] or p.prefixlen != p.max_prefixlen or not any(p.version == n.version and p.subnet_of(n) for n in LABS):
            raise ValueError('only documentation host prefixes')
        if ipaddress.ip_address(e['probe_address']).version != e['family'] or not 1 <= e['probe_port'] <= 65535:
            raise ValueError('probe endpoint')
        if e['query_type'] != ('A' if e['role'] == 'normal' else 'AAAA') or not e['query_name'].endswith('.'):
            raise ValueError('semantic query')
        if ipaddress.ip_address(e['expected']).version != (4 if e['role'] == 'normal' else 6):
            raise ValueError('expected answer family')
    return c


def semantic(reply, e):
    try:
        q = reply['question']
        if reply['rcode'] != 0 or len(q) != 1 or q[0]['Name'].lower() != e['query_name'].lower() or q[0]['Qtype'] != (1 if e['query_type'] == 'A' else 28) or q[0]['Qclass'] != 1:
            return False
        a = reply['answers']
        fields = a[0].split() if len(a) == 1 else []
        return len(fields) == 5 and fields[0].lower() == e['query_name'].lower() and fields[2:4] == ['IN', e['query_type']] and ipaddress.ip_address(fields[4]) == ipaddress.ip_address(e['expected'])
    except (KeyError, TypeError, ValueError, IndexError):
        return False


def probe(c, e, transport, timeout=2, diagnostic=None):
    started = time.monotonic()
    detail = {'transport': transport, 'rcode': None, 'outcome': 'process_error'}
    host = e['probe_address']
    endpoint = ('[' + host + ']' if ':' in host else host) + ':' + str(e['probe_port'])
    try:
        helper=c.get('query_helper')
        args=[helper or c['fixture'], 'query', transport, endpoint, e['query_name'], e['query_type']]
        if helper:args.append(str(round(timeout*1000)))
        r = subprocess.run(args, capture_output=True, text=True, timeout=timeout+(.25 if helper else 0), check=not bool(helper))
        reply = json.loads(r.stdout)
        if not isinstance(reply,dict):
            detail['outcome']='invalid_response'
            return False
        if helper and r.returncode!=0:
            detail['outcome']=reply.get('outcome') if reply.get('outcome') in ('timeout','network_error','invalid_arguments') else 'invalid_response'
            return False
        if helper and reply.get('outcome')!='response':
            detail['outcome']='invalid_response'
            return False
        healthy = semantic(reply, e)
        detail.update(rcode=reply.get('rcode'), outcome='success' if healthy else 'unexpected_answer')
        return healthy
    except subprocess.TimeoutExpired:
        detail['outcome'] = 'timeout'
        return False
    except json.JSONDecodeError:
        detail['outcome'] = 'invalid_response'
        return False
    except (subprocess.SubprocessError, OSError, ValueError):
        return False
    finally:
        if diagnostic is not None:
            detail['duration_ms'] = round((time.monotonic()-started)*1000, 2)
            diagnostic.update(detail)


def probe_round(c, timeout=3):
    # Debian python3-minimal may omit concurrent.futures. threading is sufficient
    # for these eight bounded subprocess probes; no third-party dependency.
    results = [False] * 8
    def worker(index, entry, transport):
        results[index] = probe(c, entry, transport)
    threads = [threading.Thread(target=worker, args=(i * 2 + j, e, p), daemon=True)
               for i, e in enumerate(c['entries']) for j, p in enumerate(('udp', 'tcp'))]
    deadline = time.monotonic() + timeout
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(max(0, deadline - time.monotonic()))
    if any(thread.is_alive() for thread in threads):
        raise RuntimeError('stalled probe round')
    return [results[i] and results[i+1] for i in range(0, 8, 2)]

class UpstreamGate:
    def __init__(self,failures=2,recoveries=2):
        self.enabled=False;self.good=0;self.bad=0;self.failures=failures;self.recoveries=recoveries
    def observe(self,healthy):
        self.good=self.good+1 if healthy else 0
        self.bad=self.bad+1 if not healthy else 0
        if self.good>=self.recoveries:self.enabled=True
        if self.bad>=self.failures:self.enabled=False
        return self.enabled

def upstream_attempts(c, entry, transport, timeout):
    """At most two subprocesses; never abandon a loser or overlap rounds."""
    completed=threading.Event()
    values=[False,False];details=[None,None]
    domains=('sslip.io','traefik.me')
    def attempt(index):
        e=dict(entry)
        e['query_name']='secdnshealth'+os.urandom(12).hex()+'.1-1-1-1.'+domains[index]+'.'
        e['expected']='1.1.1.1' if entry['role']=='normal' else '64:ff9b::101:101'
        detail={'role':entry['role'],'family':entry.get('family'),'provider':domains[index]}
        try:values[index]=probe(c,e,transport,timeout=timeout,diagnostic=detail)
        finally:
            details[index]=detail
            if index==0:completed.set()
    started=time.monotonic()
    primary=threading.Thread(target=attempt,args=(0,),daemon=True)
    primary.start()
    completed.wait(.25)
    threads=[primary]
    if not (completed.is_set() and values[0]):
        fallback=threading.Thread(target=attempt,args=(1,),daemon=True)
        fallback.start();threads.append(fallback)
    for thread in threads:thread.join(max(0,timeout+.75-(time.monotonic()-started)))
    if any(thread.is_alive() for thread in threads):raise RuntimeError('stalled upstream attempts')
    return any(values),[domains[i] for i,value in enumerate(values) if value],[d for d in details if d is not None]

def next_round_delay(settings, elapsed, gates):
    # A failed round remains one observation, regardless of provider count.
    # Confirm an advertised profile's first failure after a full one-second gap.
    if any(g.enabled and 0<g.bad<g.failures for g in gates):return 1.0
    return max(0,settings['interval_seconds']-elapsed)

class UpstreamHealth:
    """Independent WAN worker; the local heartbeat loop never waits for WAN."""
    def __init__(self,c,settings_path=None):
        self.config=c
        self.settings_path=settings_path
        self.settings=health_settings.load(settings_path)
        self.settings_revision=None
        self.active_revision=None
        self.lock=threading.Lock()
        self.observed=None
        self.results=[False]*4
        self.gates=[UpstreamGate() for _ in range(4)]
        self.last_success=[None]*4
        self.sources=[[] for _ in range(4)]
        self.attempts=[]
        self.thread=threading.Thread(target=self.run,daemon=True)
        self.thread.start()

    def run(self):
        while True:
            started=time.monotonic()
            # Load only between rounds. In-flight results retain their own revision.
            try: settings=health_settings.load(self.settings_path)
            except (OSError,ValueError):
                with self.lock: self.observed=None;self.results=[False]*4;self.settings_revision=None
                return
            revision=health_settings.revision(settings)
            with self.lock:
                if revision!=self.active_revision:
                    self.gates=[UpstreamGate(settings['failure_threshold'],settings['recovery_threshold']) for _ in range(4)]
                    self.results=[False]*4;self.observed=None;self.settings_revision=None
                    self.last_success=[None]*4;self.sources=[[] for _ in range(4)]
                    self.attempts=[]
                self.settings=settings;self.active_revision=revision
            results=[False]*8
            sources=[[] for _ in range(8)]
            attempts=[[] for _ in range(8)]
            stalled=[False]*8
            def query(index,entry,transport):
                try:
                    results[index],successful,attempts[index]=upstream_attempts(self.config,entry,transport,settings['probe_timeout_ms']/1000)
                    sources[index]=successful
                except RuntimeError:stalled[index]=True
            threads=[threading.Thread(target=query,args=(i*2+j,e,p),daemon=True) for i,e in enumerate(self.config['entries']) for j,p in enumerate(('udp','tcp'))]
            for thread in threads:thread.start()
            for thread in threads:thread.join(max(0,(2*settings['probe_timeout_ms']+500)/1000-(time.monotonic()-started)))
            if any(thread.is_alive() for thread in threads) or any(stalled):
                # Stop the worker rather than accumulating orphan probe rounds.
                # Main loop eventually marks this observation stale and withdraws.
                return
            with self.lock:
                self.observed=started
                self.settings_revision=revision
                healthy=[results[i] and results[i+1] for i in range(0,8,2)]
                self.results=[gate.observe(value) for gate,value in zip(self.gates,healthy)]
                for i,value in enumerate(healthy):
                    if value:self.last_success[i]=started
                self.sources=[sorted(set(sources[i]+sources[i+1])) for i in range(0,8,2)]
                self.attempts=[dict(attempt,round_started_monotonic=started) for group in attempts for attempt in group]
            time.sleep(next_round_delay(settings,time.monotonic()-started,self.gates))

    def snapshot(self, include_diagnostics=False):
        with self.lock:
            age=None if self.observed is None else time.monotonic()-self.observed
            fresh=age is not None and 0<=age<=health_settings.stale_seconds(self.settings)
            success_ages=[None if value is None else time.monotonic()-value for value in self.last_success]
            result=((list(self.results) if fresh else [False]*4),age,fresh,success_ages,list(self.sources),self.settings_revision)
            return result+([dict(attempt) for attempt in self.attempts],) if include_diagnostics else result

def announcement_flags(config_path,entries):
    if config_path is None:return [True]*4
    path=config_path.parent/'bgp-console.json'
    if not path.exists():return [True]*4
    info=path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:raise ValueError('unsafe BGP settings')
    obj=json.loads(path.read_text())
    flags=obj['announcements']
    if len(flags)!=4 or {(a['role'],a['family']) for a in flags}!={(e['role'],e['family']) for e in entries} or any(type(a['enabled']) is not bool for a in flags):raise ValueError('invalid announcements')
    by_key={(a['role'],a['family']):a['enabled'] for a in flags}
    return [by_key[e['role'],e['family']] for e in entries]


class Gate:
    def __init__(self, recover=3):
        self.enabled = False
        self.good = 0
        self.recover = recover

    def observe(self, healthy):
        self.good = self.good + 1 if healthy else 0
        desired = healthy and (self.enabled or self.good >= self.recover)
        changed = desired != self.enabled
        self.enabled = desired
        return changed, desired


def require_fresh(started, now):
    if not 0 <= now - started <= 3:
        raise RuntimeError('stale health round')


def maintenance(path):
    if path is None:
        return False
    try:
        info = path.lstat()
    except FileNotFoundError:
        return False
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022 or info.st_size > 1024:
        raise ValueError('maintenance file must be root-owned regular and not group/world writable')
    with path.open('r') as f:
        opened = os.fstat(f.fileno())
        if (opened.st_ino, opened.st_dev) != (info.st_ino, info.st_dev):
            raise ValueError('maintenance file changed during read')
        obj = json.loads(f.read(1025))
    if not isinstance(obj, dict) or set(obj) != {'withdraw'} or type(obj['withdraw']) is not bool:
        raise ValueError('invalid maintenance schema')
    return obj['withdraw']


def route(c, e, enable):
    if e['prefix'] not in c['allowed_prefixes']:
        raise ValueError('prefix not allowed')
    commands = ['configure terminal', 'router bgp ' + str(c['bgp_asn']), 'address-family ipv' + str(e['family']) + ' unicast', ('network ' if enable else 'no network ') + e['prefix'], 'end']
    args = ['vtysh', '--vty_socket', c['vty_socket'], '-d', 'bgpd']
    for command in commands:
        args += ['-c', command]
    r = subprocess.run(args, capture_output=True, text=True, timeout=2, check=False)
    diagnostics = [line.strip() for line in (r.stdout + '\n' + r.stderr).splitlines() if line.strip()]
    # FRR reports absent network statements on a clean startup. Only this exact
    # deletion diagnostic is idempotent; mixed/unknown errors remain fatal.
    if not enable and diagnostics and all(line in ("% Can't find static route specified", "Can't find static route specified") for line in diagnostics):
        return
    if r.returncode != 0 or '%' in r.stdout or '%' in r.stderr:
        raise RuntimeError('FRR rejected route operation')


def run(c, maintenance_path=None):
    c = validate(c)
    gates = [Gate() for _ in c['entries']]
    upstream=UpstreamHealth(c,maintenance_path.parent/'health-settings.json' if maintenance_path else None)
    # Always start withdrawn; previous process state is never trusted.
    for e in c['entries']:
        route(c, e, False)
    sequence = 0
    while True:
        started = time.monotonic()
        local = probe_round(c)
        upstream_ok,upstream_age,upstream_fresh,upstream_success_ages,upstream_sources,settings_revision,upstream_attempts_detail=upstream.snapshot(include_diagnostics=True)
        observations=[a and b for a,b in zip(local,upstream_ok)]
        # No heartbeat/advertisement from a stale observation round.
        require_fresh(started, time.monotonic())
        withdrawn = maintenance(maintenance_path)
        flags=announcement_flags(maintenance_path,c['entries'])
        for e, gate, healthy,admin_enabled in zip(c['entries'], gates, observations,flags):
            changed, enabled = gate.observe(healthy and not withdrawn and admin_enabled)
            if changed:
                route(c, e, enabled)
        sequence += 1
        reasons=['local DNS check failed' if not local[i] else ('upstream observation stale' if not upstream_fresh else ('external DNS canary failed' if not upstream_ok[i] else 'ready')) for i in range(4)]
        print(json.dumps({'type': 'health', 'sequence': sequence, 'observed_monotonic': started, 'healthy': observations, 'local_healthy':local,'upstream_healthy':upstream_ok if upstream_fresh else [None]*4,'upstream_age_seconds':upstream_age,'upstream_success_ages':upstream_success_ages,'upstream_sources':upstream_sources,'upstream_attempts':upstream_attempts_detail,'health_settings_revision':settings_revision,'upstream_worker_failed':not upstream.thread.is_alive(),'reasons':reasons,'maintenance': withdrawn, 'advertised': [g.enabled for g in gates]}), flush=True)
        time.sleep(max(0, 1 - (time.monotonic() - started)))


if __name__ == '__main__':
    # Supervisor owns all children and kills FRR if this process exits for ANY reason.
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    config_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
    run(json.loads(config_path.read_text()), config_path.parent / 'maintenance.json')
