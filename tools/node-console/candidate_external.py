"""Enrolled external BGP peers. Browser drafts never confer transport authority."""
import hashlib
import ipaddress
import json
import re
import subprocess
import time
import candidate_status as c


def policy(node):
    path = c.BASE / 'external-policy.json'
    value = c.read(path) if path.exists() else {'schema': 1, 'node': node, 'peers': []}
    if not isinstance(value, dict) or set(value) != {'schema', 'node', 'peers'} or type(value['schema']) is not int or value['schema'] != 1 or value['node'] != node or not isinstance(value['peers'], list) or len(value['peers']) > 8:
        raise ValueError('external enrollment schema')
    ids, addresses = set(), {a for pair in c.ADDRESSES.values() for a in pair}
    import candidate_bgp
    client = candidate_bgp.test_client()
    if client: addresses.update((client['ipv4'], client['ipv6']))
    for p in value['peers']:
        keys = {'id', 'address', 'transport_family', 'local_source', 'local_asn', 'remote_asn', 'port', 'allowed_afis', 'allowed_exports'}
        if not isinstance(p, dict) or set(p) != keys or not isinstance(p['id'], str) or not re.fullmatch('[a-z][a-z0-9-]{0,31}', p['id']) or p['id'] in ids:
            raise ValueError('external enrollment identity')
        ids.add(p['id'])
        for key in ('address', 'local_source'):
            a = ipaddress.ip_address(p[key])
            if type(p['transport_family']) is not int or a.version != p['transport_family'] or str(a) != p[key] or a.is_unspecified or a.is_multicast or a.is_loopback or a.is_link_local:
                raise ValueError('external literal transport')
        if p['address'] in addresses or p['address'] == p['local_source']:
            raise ValueError('external transport collision')
        addresses.add(p['address'])
        for key in ('local_asn', 'remote_asn'):
            if type(p[key]) is not int or not 1 <= p[key] <= 4294967294 or p[key] == 23456:
                raise ValueError('external ASN')
        if p['local_asn'] == p['remote_asn'] or type(p['port']) is not int or not 1 <= p['port'] <= 65535:
            raise ValueError('external eBGP transport')
        if not isinstance(p['allowed_afis'], list) or not p['allowed_afis'] or any(type(f) is not int or f not in (4, 6) for f in p['allowed_afis']) or len(set(p['allowed_afis'])) != len(p['allowed_afis']):
            raise ValueError('external AFIs')
        if not isinstance(p['allowed_exports'], list) or any(not isinstance(x, str) or x not in c.PREFIXES or (6 if ':' in x else 4) not in p['allowed_afis'] for x in p['allowed_exports']) or len(set(p['allowed_exports'])) != len(p['allowed_exports']):
            raise ValueError('external exports')
    return value


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def validate(node, entries, enrolled=None):
    enrolled = policy(node) if enrolled is None else enrolled
    if not isinstance(entries, list) or len(entries) > 8:
        raise ValueError('external entries')
    lookup = {p['id']: p for p in enrolled['peers']}
    seen = set()
    for p in entries:
        if not isinstance(p, dict) or set(p) != {'id', 'name', 'enabled', 'afis', 'keepalive_seconds', 'hold_seconds', 'exports'} or p['id'] not in lookup or p['id'] in seen:
            raise ValueError('external peer is not enrolled')
        seen.add(p['id']); allowed = lookup[p['id']]
        if not isinstance(p['name'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9 ._:@-]{0,95}', p['name']) or type(p['enabled']) is not bool:
            raise ValueError('external name or enable')
        if not isinstance(p['afis'], list) or not p['afis'] or any(type(f) is not int or f not in allowed['allowed_afis'] for f in p['afis']) or len(set(p['afis'])) != len(p['afis']):
            raise ValueError('external AFI authorization')
        k, h = p['keepalive_seconds'], p['hold_seconds']
        if type(k) is not int or type(h) is not int or not 1 <= k <= 30 or not 3 <= h <= 90 or h < 3*k:
            raise ValueError('external timer bounds')
        if not isinstance(p['exports'], list) or any(not isinstance(x, str) or x not in allowed['allowed_exports'] or (6 if ':' in x else 4) not in p['afis'] for x in p['exports']) or len(set(p['exports'])) != len(p['exports']):
            raise ValueError('external export authorization')
    return sorted(entries, key=lambda p: p['id'])


def render(node, entries, enrolled):
    """Return policy/global/AF lines; no networks or redistribution are added."""
    validate(node, entries, enrolled)
    lookup = {p['id']: p for p in enrolled['peers']}
    policies = ['route-map EXTERNAL-DENY deny 10'] if entries else []
    neighbors, afis = [], {4: [], 6: []}
    for entry in entries:
        p = lookup[entry['id']]; a = p['address']; tag = 'EXT-' + p['id']
        neighbors += [f' neighbor {a} remote-as {p["remote_asn"]}', f' neighbor {a} port {p["port"]}', f' neighbor {a} update-source {p["local_source"]}', f' neighbor {a} timers {entry["keepalive_seconds"]} {entry["hold_seconds"]}']
        if p['local_asn'] != c.NODES[node]:
            neighbors.append(f' neighbor {a} local-as {p["local_asn"]} no-prepend replace-as')
        if p['transport_family'] == 6 and 4 in entry['afis']: neighbors.append(f' neighbor {a} capability extended-nexthop')
        if not entry['enabled']: neighbors.append(f' neighbor {a} shutdown')
        for family in entry['afis']:
            name = tag + '-' + str(family); kind = 'ip' if family == 4 else 'ipv6'
            prefixes = sorted(x for x in entry['exports'] if (':' in x) == (family == 6))
            if prefixes:
                for i, prefix in enumerate(prefixes): policies.append(f'{kind} prefix-list {name} seq {(i+1)*10} permit {prefix}')
                policies += [f'route-map {name} permit 10', f' match {kind} address prefix-list {name}', ' match as-path LOCAL-ONLY']
            else: policies.append(f'route-map {name} deny 10')
            afis[family] += [f'  neighbor {a} activate', f'  neighbor {a} route-map EXTERNAL-DENY in', f'  neighbor {a} route-map {name} out']
    return policies, neighbors, afis


def query(command, deadline):
    remaining = deadline - time.monotonic()
    if remaining <= 0: raise RuntimeError('external observation budget')
    result = subprocess.run(['vtysh', '--vty_socket', str(c.BASE/'state'), '-d', 'bgpd', '-c', command], capture_output=True, text=True, timeout=min(remaining, 2))
    if result.returncode or len(result.stdout) > 262144: raise RuntimeError('external observation unavailable')
    return result.stdout


def runtime_matches(node, entries, enrolled, deadline, diagnostic=None):
    policies, neighbors, afis = render(node, entries, enrolled)
    addresses = {p['address'] for p in enrolled['peers']}
    def selected(lines):
        family = 0; found = []
        for line in lines:
            line = line.strip()
            if line == 'address-family ipv4 unicast': family = 4
            elif line == 'address-family ipv6 unicast': family = 6
            elif line == 'exit-address-family': family = 0
            elif line.startswith('neighbor ') and line.split()[1] in addresses: found.append((family, line))
        return sorted(found)
    expected = neighbors[:]
    for family in (4, 6): expected += [f'address-family ipv{family} unicast', *afis[family], 'exit-address-family']
    running = query('show running-config', deadline)
    names = {'EXTERNAL-DENY'} | {'EXT-'+p['id']+'-'+str(f) for p in enrolled['peers'] for f in (4,6)}
    def definitions(lines):
        found=[]; block=None
        for raw in lines:
            line=' '.join(raw.split())
            if not line or line in ('!', 'exit'): continue
            if line.startswith('route-map '):
                block=line if line.split()[1] in names else None
                if block: found.append((block,''))
            elif raw[:1].isspace() and block:
                found.append((block,line))
            else:
                block=None
                parts=line.split()
                if line.startswith('bgp as-path access-list LOCAL-ONLY '):
                    # FRR 10.3 renders the implicit sequence as "seq 5".
                    # Ignore only this rule identifier, not action, regex, or
                    # multiplicity: additional rules still fail exact equality.
                    match = re.fullmatch(r'bgp as-path access-list LOCAL-ONLY seq ([1-9][0-9]{0,9}) (permit|deny) (.+)', line)
                    if match and int(match[1]) <= 4294967295:
                        line = 'bgp as-path access-list LOCAL-ONLY '+match[2]+' '+match[3]
                    found.append(('as-path',line))
                elif len(parts)>2 and parts[0] in ('ip','ipv6') and parts[1]=='prefix-list' and parts[2] in names:found.append(('prefix-list',line))
        return sorted(found)
    expected_definitions=['bgp as-path access-list LOCAL-ONLY permit ^$', *policies]
    actual_neighbors, expected_neighbors = selected(running.splitlines()), selected(expected)
    actual_policy, expected_policy = definitions(running.splitlines()), definitions(expected_definitions)
    matches = actual_neighbors == expected_neighbors and actual_policy == expected_policy
    if diagnostic is not None:
        # Expected lines contain only validated enrolled inputs. Never persist
        # arbitrary running lines: FRR may contain neighbor passwords/descriptions.
        diagnostic.update(matches=matches, missing_neighbors=[x for x in expected_neighbors if x not in actual_neighbors][:128],
                          missing_policy=[x for x in expected_policy if x not in actual_policy][:128],
                          unexpected_neighbors=[{'family':x[0], 'sha256':hashlib.sha256(x[1].encode()).hexdigest()} for x in actual_neighbors if x not in expected_neighbors][:128],
                          unexpected_policy=[{'sha256':hashlib.sha256(repr(x).encode()).hexdigest()} for x in actual_policy if x not in expected_policy][:128])
    return matches


def observe(node, entries, enrolled, deadline=None):
    """Bounded external observations never contribute to DNS/mesh quorum."""
    lookup = {p['id']: p for p in enrolled['peers']}
    observations = []
    deadline = time.monotonic() + 4 if deadline is None else deadline
    summary = {}; verified = False
    try:
        verified = runtime_matches(node, entries, enrolled, deadline)
        if entries: summary = json.loads(query('show bgp summary json', deadline))
    except (KeyError, TypeError, ValueError, RuntimeError, OSError, subprocess.SubprocessError): pass
    for entry in entries:
        p = lookup[entry['id']]
        for family in entry['afis']:
            item = {'id': entry['id'], 'family': family, 'state': 'Unknown', 'prefixes': None, 'observed': False, 'runtime_verified': verified}
            try:
                peer = summary['ipv%dUnicast' % family]['peers'][p['address']]
                if not isinstance(peer, dict) or not isinstance(peer.get('state'), str): raise ValueError('external state')
                item['state'] = peer['state']
                if not entry['enabled'] and verified and peer['state'] != 'Established':
                    # An exact running shutdown + no established session proves withdrawal.
                    prefixes = []
                else:
                    routes = json.loads(query('show bgp ipv%d unicast neighbors %s advertised-routes json' % (family, p['address']), deadline))
                    prefixes = c.advertised_prefixes(routes, family)
                if not set(prefixes) <= set(entry['exports']): raise ValueError('external unexpected export')
                item.update(prefixes=prefixes, observed=True)
            except (KeyError, TypeError, ValueError, RuntimeError, OSError, subprocess.SubprocessError): pass
            observations.append(item)
    return observations


def failure_diagnostic(node, config, enrolled):
    """Failure-only, bounded native evidence; never exposes unfiltered FRR text."""
    deadline = time.monotonic()+4
    entries = config.get('external_peers', [])
    result = {'schema':1, 'runtime':{}, 'peers':[], 'complete':True}
    try: runtime_matches(node, entries, enrolled, deadline, result['runtime'])
    except Exception: result['runtime']={'available':False};result['complete']=False
    try: summary=json.loads(query('show bgp summary json', deadline)) if entries else {}
    except Exception: summary={};result['complete']=False
    lookup={p['id']:p for p in enrolled['peers']}
    states={'Idle','Active','Connect','OpenSent','OpenConfirm','Established','Idle (Admin)'}
    for entry in entries:
        for family in entry['afis']:
            item={'id':entry['id'],'family':family,'expected_enabled':entry['enabled'],
                  'allowed_exports':[p for p in entry['exports'] if (':' in p)==(family==6)],
                  'state':'Unknown','advertised_prefixes':None,'advertisement_schema_known':False}
            try:
                peer=summary['ipv%dUnicast'%family]['peers'][lookup[entry['id']]['address']]
                item['state']=peer.get('state') if peer.get('state') in states else 'Unknown'
                for key in ('remoteAs','localAs','pfxRcd','pfxSnt','connectionsEstablished'):
                    if type(peer.get(key)) is int and 0<=peer[key]<=4294967295:item[key]=peer[key]
            except (KeyError,TypeError): result['complete']=False
            try:
                routes=json.loads(query('show bgp ipv%d unicast neighbors %s advertised-routes json'%(family,lookup[entry['id']]['address']),deadline))
                values=routes.get('advertisedRoutes')
                if not isinstance(values,dict) or len(values)>16:raise ValueError('unrecognized advertisements')
                prefixes=[]
                for prefix in values:
                    parsed=ipaddress.ip_network(prefix)
                    if str(parsed)!=prefix or parsed.version!=family:raise ValueError('noncanonical prefix')
                    prefixes.append(prefix)
                item.update(advertised_prefixes=sorted(prefixes),advertisement_schema_known=True)
            except Exception: result['complete']=False
            result['peers'].append(item)
    return result
