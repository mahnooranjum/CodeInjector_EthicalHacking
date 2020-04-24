#!/usr/bin/env python

import subprocess
subprocess.call("sudo iptables -I INPUT -j NFQUEUE --queue-num 0", shell=True)
subprocess.call("sudo iptables -I OUTPUT -j NFQUEUE --queue-num 0", shell=True)
