#!/usr/bin/env python3

import subprocess
subprocess.call("sudo iptables --flush", shell=True)
