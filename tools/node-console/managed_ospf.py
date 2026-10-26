"""Foreground companion for root-enrolled candidate OSPF, under systemd.

The unit supplies private /etc/frr and /var/lib/frr mounts. It shares the
existing zebra backend intentionally and manages only its exact enrolled OSPF
kernel-import maps. It never starts zebra or changes DNS, DHCP, interface
addresses, BGP policy, or firewall rules.
"""
import hashlib
import ipaddress
import json
import os
import pathlib
import re
import signal
import stat
import subprocess
import sys
import time


def validate(config):
    required={'interface','management_ipv4','local_link_local','identity_interface',
              'identity_addresses','zebra_state','files','firewall_sha256'}
    if set(config)!=required:raise ValueError('unexpected enrollment fields')
    for key in ('interface','identity_interface'):
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,15}',config[key]):raise ValueError('invalid interface')
    if config['interface']==config['identity_interface']:raise ValueError('identity must be separate')
    if ipaddress.ip_address(config['management_ipv4']).version!=4:raise ValueError('management IPv4 required')
    local=ipaddress.ip_address(config['local_link_local'])
    if local.version!=6 or not local.is_link_local:raise ValueError('interface-scoped IPv6 link-local required')
    identities=config['identity_addresses']
    if len(identities)!=3 or len(set(identities))!=3:raise ValueError('three distinct identities required')
    parsed=[ipaddress.ip_interface(value) for value in identities]
    if sorted(p.version for p in parsed)!=[4,6,6] or any(p.network.prefixlen!=p.max_prefixlen for p in parsed):
        raise ValueError('identities must be one IPv4 and two IPv6 host addresses')
    if not pathlib.PurePosixPath(config['zebra_state']).is_absolute():raise ValueError('absolute zebra state required')
    if set(config['files'])!={'ospfd.conf','ospf6d.conf','policy.conf'}:raise ValueError('exact configuration files required')
    if any(not re.fullmatch(r'[0-9a-f]{64}',value) for value in [*config['files'].values(),config['firewall_sha256']]):
        raise ValueError('invalid enrollment digest')
    return config


def address_ready(config, entries):
    by_name={item['ifname']:item for item in entries}
    def addresses(name):
        item=by_name.get(name,{})
        if 'UP' not in item.get('flags',[]):return set()
        return {str(ipaddress.ip_address(a['local'])) for a in item.get('addr_info',[])
                if not any(a.get(flag,False) or flag in a.get('flags',[]) for flag in ('tentative','dadfailed'))}
    management=addresses(config['interface'])
    identity={a for a in addresses(config['identity_interface']) if not ipaddress.ip_address(a).is_link_local}
    return ({a for a in management if ipaddress.ip_address(a).version==4}=={str(ipaddress.ip_address(config['management_ipv4']))}
            and str(ipaddress.ip_address(config['local_link_local'])) in management
            and identity=={str(ipaddress.ip_interface(a).ip) for a in config['identity_addresses']})


def policy_attached(four,six):
    return (any(line.split()==['ospf',':','SD_STAGE4'] for line in four.splitlines())
            and any(line.split()==['ospf6',':','SD_STAGE6'] for line in six.splitlines()))


def managed_policy(text):
    """Compare the whole owned map bodies, not merely attachment names."""
    selected=[];current=None
    for raw in text.splitlines():
        line=' '.join(raw.split())
        if line in ('!','exit','end'):
            current=None;continue
        if line.startswith('route-map '):
            current=line if line.split()[1] in ('SD_STAGE4','SD_STAGE6') else None
            if current:selected.append(current)
        elif current and raw[:1].isspace():selected.append(current+'|'+line)
        else:
            current=None
            if (line.startswith('ip prefix-list SD_ALLOW4 ') or line.startswith('ipv6 prefix-list SD_ALLOW6 ')
                    or line.startswith('ip protocol ospf ') or line.startswith('ipv6 protocol ospf6 ')):
                selected.append(line)
    return sorted(selected)


def firewall_digest(value):
    # Kernel-assigned handles change across reboot. Counters must not be enrolled.
    def clean(obj):
        if isinstance(obj,dict):return {k:clean(v) for k,v in obj.items() if k not in ('handle','metainfo')}
        if isinstance(obj,list):return [clean(v) for v in obj if not isinstance(v,dict) or 'metainfo' not in v]
        return obj
    return hashlib.sha256(json.dumps(clean(value),sort_keys=True,separators=(',',':')).encode()).hexdigest()


def verify_file(path,digest=None):
    st=path.lstat()
    if not stat.S_ISREG(st.st_mode) or st.st_uid!=0 or st.st_mode & 0o022:
        raise RuntimeError('unsafe root-owned configuration: '+str(path))
    if digest and hashlib.sha256(path.read_bytes()).hexdigest()!=digest:
        raise RuntimeError('enrolled configuration changed: '+str(path))


def run(args):
    result=subprocess.run(args,capture_output=True,text=True,timeout=2)
    combined=result.stdout+'\n'+result.stderr
    if result.returncode or any(word in combined.lower() for word in ('no such command','unknown command','failed','error','%')):
        raise RuntimeError('native command rejected: '+combined[-2000:])
    return result.stdout


def vty(directory,daemon,command,base):
    return run(['vtysh','--vty_socket',str(directory),'--config_dir',str(base/'etc'),'-d',daemon,'-c',command])


def configure_policy(state,base,commands):
    args=['vtysh','--vty_socket',str(state),'--config_dir',str(base/'etc'),'-d','mgmtd','-c','configure terminal']
    for line in commands:
        if line.strip() and line.strip()!='!':args+=['-c',line.strip()]
    return run([*args,'-c','end'])


def policy_unowned(four,six,existing):
    return (any(line.split()==['ospf',':','none'] for line in four.splitlines())
            and any(line.split()==['ospf6',':','none'] for line in six.splitlines())
            and not any(name in existing for name in ('SD_STAGE4','SD_STAGE6','SD_ALLOW4','SD_ALLOW6')))


def load_when_unowned(read_state,loader):
    four,six,existing=read_state()
    if not policy_unowned(four,six,existing):raise RuntimeError('OSPF policy already owned; refusing overwrite')
    loader()


def incarnation(state):
    pid=int((state/'zebra.pid').read_text())
    if pathlib.Path(f'/proc/{pid}/comm').read_text().strip()!='zebra':raise RuntimeError('zebra PID mismatch')
    return pid,pathlib.Path(f'/proc/{pid}/stat').read_text().rsplit(')',1)[1].split()[19]


def stop(children,names):
    errors=[]
    for name in names:
        child=children.get(name)
        if child is None:continue
        if child.poll() is not None:
            children.pop(name);continue
        try:
            child.terminate()
            try:child.wait(timeout=3)
            except subprocess.TimeoutExpired:child.kill();child.wait(timeout=3)
            # Never discard ownership until wait confirms exit.
            children.pop(name)
        except Exception as error:errors.append(name+': '+str(error))
    if errors:raise RuntimeError('; '.join(errors))


def main(base):
    base=pathlib.Path(base).resolve(strict=True)
    enrollment=base/'enrollment.json';verify_file(enrollment)
    config=validate(json.loads(enrollment.read_text()))
    for name,digest in config['files'].items():verify_file(base/name,digest)
    import pwd
    frr=pwd.getpwnam('frr')
    for name in config['files']:
        if (base/name).stat().st_gid!=frr.pw_gid or stat.S_IMODE((base/name).stat().st_mode)!=0o640:
            raise RuntimeError('configuration must be root:frr 0640')
    for name in ('state','history'):
        if (base/name).stat().st_uid!=frr.pw_uid or (base/name).stat().st_mode & 0o022:
            raise RuntimeError('precreated frr-owned state directory required')
    expected_policy=managed_policy((base/'policy.conf').read_text())
    if not expected_policy:raise RuntimeError('empty enrolled policy')
    # Verify systemd private mounts, rather than trusting only unit settings.
    if os.stat('/etc/frr').st_ino!=os.stat(base/'etc').st_ino or os.stat('/var/lib/frr').st_ino!=os.stat(base/'history').st_ino:
        raise RuntimeError('private config/history mounts absent')
    if os.readlink('/proc/self/ns/mnt')==os.readlink('/proc/1/ns/mnt'):
        raise RuntimeError('private mount namespace absent')
    state=base/'state';zebra=pathlib.Path(config['zebra_state'])
    for sock in ('mgmtd_be.sock','mgmtd_fe.sock'):
        if os.path.lexists('/run/frr/'+sock):raise RuntimeError('management backend already owned or stale')
    def current_policy():
        existing='\n'.join(vty(zebra,'zebra',command,base) for command in ('show ip prefix-list','show ipv6 prefix-list','show route-map'))
        return vty(zebra,'zebra','show ip protocol',base),vty(zebra,'zebra','show ipv6 protocol',base),existing
    if not policy_unowned(*current_policy()):raise RuntimeError('existing policy cannot be overwritten')
    if (base/'etc/mgmtd.conf').exists():raise RuntimeError('implicit mgmtd startup configuration forbidden')
    children={};sockets={};previous=None;last_status=None;policy_loaded=False
    try:
        children['mgmtd']=subprocess.Popen(['/usr/lib/frr/mgmtd','-i',str(state/'mgmtd.pid'),
            '--vty_socket',str(state),'-P','0','-u','frr','-g','frr'],stdin=subprocess.DEVNULL)
        while True:
            for sock in ('mgmtd_be.sock','mgmtd_fe.sock'):
                path=pathlib.Path('/run/frr')/sock
                if path.exists() and path not in sockets:
                    st=path.stat();sockets[path]=(st.st_dev,st.st_ino)
            if children['mgmtd'].poll() is not None:raise RuntimeError('owned mgmtd exited')
            if any(p.poll() is not None for n,p in children.items() if n!='mgmtd'):
                raise RuntimeError('owned OSPF daemon exited')
            try:
                current=incarnation(zebra)
                if previous is not None and current!=previous:stop(children,('ospfd','ospf6d'))
                previous=current
                for name,digest in config['files'].items():verify_file(base/name,digest)
                if not policy_loaded:
                    if 'Total' not in vty(state,'mgmtd','show mgmt backend-adapter all',base):
                        raise RuntimeError('mgmtd frontend not ready')
                    load_when_unowned(current_policy,lambda:configure_policy(state,base,(base/'policy.conf').read_text().splitlines()))
                    policy_loaded=True
                ready=address_ready(config,json.loads(run(['ip','-j','address','show'])))
                if not ready:raise RuntimeError('enrolled interface/lease/identity mismatch')
                if firewall_digest(json.loads(run(['nft','-j','list','table','inet','secdns_staged_ospf'])))!=config['firewall_sha256']:
                    raise RuntimeError('enrolled OSPF firewall gate mismatch')
                if not policy_attached(vty(zebra,'zebra','show ip protocol',base),vty(zebra,'zebra','show ipv6 protocol',base)):
                    raise RuntimeError('exact-loopback kernel policy not attached')
                if managed_policy(vty(state,'mgmtd','show running-config',base))!=expected_policy:
                    raise RuntimeError('owned policy body differs from enrollment')
                # Readiness is semantic; no daemon starts merely because a socket exists.
                if 'Total' not in vty(state,'mgmtd','show mgmt backend-adapter all',base):
                    raise RuntimeError('mgmtd frontend not ready')
                for daemon in ('ospfd','ospf6d'):
                    if daemon not in children:
                        children[daemon]=subprocess.Popen(['/usr/lib/frr/'+daemon,'-f',str(base/(daemon+'.conf')),
                            '-i',str(state/(daemon+'.pid')),'-z',str(zebra/'zserv.api'),'--vty_socket',str(state),
                            '-P','0','-u','frr','-g','frr'],stdin=subprocess.DEVNULL)
                status={'ready':True,'zebra_pid':current[0]}
            except (RuntimeError,OSError,ValueError) as error:
                stop(children,('ospfd','ospf6d'))
                status={'ready':False,'reason':str(error)}
            if status!=last_status:
                print(json.dumps(status),flush=True);last_status=status
            time.sleep(.5)
    finally:
        errors=[]
        try:stop(children,('ospfd','ospf6d'))
        except Exception as error:errors.append(str(error))
        if policy_loaded and not errors and not any(name in children for name in ('ospfd','ospf6d')):
            try:
                if managed_policy(vty(state,'mgmtd','show running-config',base))!=expected_policy:
                    raise RuntimeError('policy ownership changed; retaining policy')
                configure_policy(state,base,['no ip protocol ospf route-map SD_STAGE4',
                    'no ipv6 protocol ospf6 route-map SD_STAGE6','no route-map SD_STAGE4',
                    'no route-map SD_STAGE6','no ip prefix-list SD_ALLOW4','no ipv6 prefix-list SD_ALLOW6'])
            except Exception as error:errors.append(str(error))
        try:stop(children,('mgmtd',))
        except Exception as error:errors.append(str(error))
        if 'mgmtd' not in children:
            for path,identity in sockets.items():
                if path.exists() and (path.stat().st_dev,path.stat().st_ino)==identity:path.unlink()
        if errors:raise RuntimeError('companion cleanup: '+'; '.join(errors))


if __name__=='__main__':
    signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
    signal.signal(signal.SIGINT,lambda *_:sys.exit(0))
    main(sys.argv[1])
