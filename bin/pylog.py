#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Main executable

import os
import sys
import imp
import inspect
import optparse

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.dirname(currentdir)
sys.path.insert(0,parentdir) 

from pylogwatch.logwlib import PyLogConf
from pylogwatch.utils import lockfile


def load_cfg_module (cfgpath):
    try:
        return imp.load_source ('PyLogConfig',os.path.realpath(cfgpath))
    except ImportError, err:
        sys.exit ('Cannot load config file %s: %s' % (cfgpath, err))

if __name__=='__main__':
    p = optparse.OptionParser()
    p.add_option('--config', '-c', default="~/pylogconf.py", help="Filesystem path to (python) configuration file [default: %default]")
    options, arguments = p.parse_args()

    # Check if we can obtain a lock - make sure we're the only process on this config
    lockfn = os.path.realpath(options.config) + '.lck'
    lockfd = open(lockfn, 'w')
    if not lockfile(lockfd):
        sys.exit ('Cannot obtain a lock on %s' %  lockfn)

    cfgmod = load_cfg_module(options.config)
    pl = PyLogConf(cfgmod)
    pl.run()
