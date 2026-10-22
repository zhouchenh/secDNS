"""Validated upstream-only settings shared by controller and candidate console."""
import hashlib
import json
import math
import os
import stat

DEFAULT = dict(interval_seconds=15, probe_timeout_ms=2500, failure_threshold=2, recovery_threshold=2)
BOUNDS = dict(interval_seconds=(3,15), probe_timeout_ms=(500,2500), failure_threshold=(2,3), recovery_threshold=(2,5))

def validate(config):
    if not isinstance(config,dict) or set(config)!=set(BOUNDS): raise ValueError('health settings fields')
    for key,(low,high) in BOUNDS.items():
        if type(config[key]) is not int or not low<=config[key]<=high: raise ValueError('health settings range')
    if 2*config['probe_timeout_ms']+500>config['interval_seconds']*1000: raise ValueError('probe budget exceeds interval')
    return dict(config)

def revision(config):
    return hashlib.sha256(json.dumps(validate(config),sort_keys=True,separators=(',',':')).encode()).hexdigest()

def stale_seconds(config):
    return 2*config['interval_seconds']+math.ceil(2*config['probe_timeout_ms']/1000)+1

def load(path):
    if path is None:return dict(DEFAULT)
    try:info=path.lstat()
    except FileNotFoundError:return dict(DEFAULT)
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022 or info.st_size>2048: raise ValueError('unsafe health settings')
    with path.open() as f:
        opened=os.fstat(f.fileno())
        if (opened.st_ino,opened.st_dev)!=(info.st_ino,info.st_dev): raise ValueError('health settings changed while opening')
        return validate(json.loads(f.read(2049)))
