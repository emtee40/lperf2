#!/usr/bin/env python3
#
# ---------------------------------------------------------------
# * Copyright (c) 2018-2023
# * Broadcom Corporation
# * All Rights Reserved.
# *---------------------------------------------------------------
# Redistribution and use in source and binary forms, with or without modification, are permitted
# provided that the following conditions are met:
#
# Redistributions of source code must retain the above copyright notice, this list of conditions
# and the following disclaimer.  Redistributions in binary form must reproduce the above copyright
# notice, this list of conditions and the following disclaimer in the documentation and/or other
# materials provided with the distribution.  Neither the name of the Broadcom nor the names of
# contributors may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
# FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR
# CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
# IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
# OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
# Author Robert J. McMahon, Broadcom LTD
# Date Sept 2023
import shutil
import logging
import flows
import argparse
import time, datetime
import os,sys
import asyncio, sys
import ssh_nodes
import re

from datetime import datetime as datetime, timezone
from flows import *
from ssh_nodes import *

parser = argparse.ArgumentParser(description='Run an isochronous UDP data stream')
parser.add_argument('-s','--server', type=str, default="10.19.85.106", required=False, help='host to run iperf server')
parser.add_argument('-c','--client', type=str, default="10.19.85.202", required=False, help='host to run iperf client')
parser.add_argument('--srcip', type=str, default="192.168.1.15",required=False, help='iperf source ip address')
parser.add_argument('-d','--dstip', type=str, default="192.168.1.231",required=False, help='iperf destination ip address')
parser.add_argument('--srcdev', type=str, default='enp2s0', required=False, help='server device name')
parser.add_argument('--dstdev', type=str, default='eth1', required=False, help='client device name')
parser.add_argument('--srctype', type=str, default='wired', required=False, help='server link type')
parser.add_argument('--dsttype', type=str, default='wireless', required=False, help='client link type')
parser.add_argument('--srclinkspeed', type=str, default='2.5G', required=False, help='client link speed')
parser.add_argument('-i','--interval', type=float, required=False, default=1, help='iperf report interval')
parser.add_argument('-l','--length', type=int, required=False, default=1470, help='udp payload size')
parser.add_argument('-n','--runcount', type=int, required=False, default=5, help='number of runs')
parser.add_argument('-t','--time', type=float, default=10, required=False, help='time or duration to run traffic')
parser.add_argument('-w','--window', type=str, default='128K', required=False, help='socket window size')
parser.add_argument('-O','--offered_load', type=str, default="10mpps", required=False, help='offered load; <fps>:<mean>,<variance>')
parser.add_argument('-T','--title', type=str, default="UDP Single Flow", required=False, help='title for graphs')
parser.add_argument('-S','--tos', type=str, default='ac_be', required=False, help='type of service or access class; BE, VI, VO or BK')
parser.add_argument('-o','--output_directory', type=str, required=False, default='./data', help='output directory')
parser.add_argument('--qdisc', type=str, required=False, default='fq', help='set the tc qdisc')
parser.add_argument('--tc_bin', type=str, required=False, default='/usr/sbin/tc', help='set the tc command')
parser.add_argument('--loglevel', type=str, required=False, default='INFO', help='python logging level, e.g. INFO or DEBUG')

def link2speed(txt) :
    switcher = {
        "1G" : "1000",
        "2.5G" : "2500",
        "5G" : "5000",
        "10G" : "10000",
    }
    return switcher.get(txt.upper(), None)

args = parser.parse_args()

if args.dsttype == "wireless" :
    args.server = '10.19.85.106'
    args.dstdev = 'eth1'
    args.dstip = '192.168.1.231'
else :
    args.server = '10.19.85.124'
    args.dstdev = 'enp2s0f0'
    args.dstip = '192.168.1.11'

logfilename='test.log'
separator = '_'
datapath = separator.join([args.output_directory, args.srclinkspeed, args.dsttype, ">", args.srctype])
if not os.path.exists(datapath):
    print('Making log directory {}'.format(datapath))
    os.makedirs(datapath)

fqlogfilename = os.path.join(datapath, logfilename)
print('Writing log to {}'.format(fqlogfilename))

FORMAT = '%(asctime)s %(levelname)-8s %(module)-9s  %(message)s'
formatter = logging.Formatter(FORMAT)
logger = logging.getLogger()
logging.basicConfig(filename=fqlogfilename, level=logging.INFO, format=FORMAT)
logging.getLogger('asyncio').setLevel(logging.INFO)

loop = asyncio.get_event_loop()
loop.set_debug(False)
ssh_node.loop.set_debug(False)
loop = asyncio.get_event_loop()

plottitle='{} {} {} {} {} bytes qdisc={} {}'.format(args.title, args.dsttype, args.offered_load, args.tos, args.length, args.qdisc, datapath)


duta = ssh_node(name='DUTA', ipaddr=args.client, device='enp2s0', console=True, ssh_speedups=False)
dutb = ssh_node(name='DUTB', ipaddr=args.server, device='eth1', console=True, ssh_speedups=False)
duts = [duta, dutb]
ssh_node.open_consoles()

duta.rexec(cmd='/usr/bin/uname -r'.format(args.tc_bin, args.srcdev, args.qdisc))
dutb.rexec(cmd='/usr/bin/uname -r'.format(args.tc_bin, args.srcdev, args.qdisc))
duta.rexec(cmd='/usr/local/bin/iperf -v')
dutb.rexec(cmd='/usr/local/bin/iperf -v')
duta.rexec(cmd='{} qdisc replace dev {} root {}'.format(args.tc_bin, args.srcdev, args.qdisc))
dutb.rexec(cmd='{} qdisc replace dev {} root {}'.format(args.tc_bin, args.dstdev, args.qdisc))
duta.rexec(cmd='{} qdisc show'.format(args.tc_bin))
dutb.rexec(cmd='{} qdisc show'.format(args.tc_bin))

if args.srclinkspeed:
    linkspeed = link2speed(args.srclinkspeed)
    duta.rexec(cmd='/usr/sbin/ethtool -s {} speed {} autoneg off'.format(args.srcdev, linkspeed))
    time.sleep(2)
duta.rexec(cmd='/usr/sbin/ethtool {}'.format(args.srcdev))

flows = [iperf_flow(name="UDP", user='root', server=dutb, client=duta, proto='UDP', offered_load=args.offered_load, interval=args.interval, dstip=args.dstip, tos=args.tos, length=args.length, latency=True, window=args.window)]

for i in range(args.runcount) :
    print("Running ({}) traffic with load {} for {} seconds".format(str(i), args.offered_load, args.time))
    runlog = logging.FileHandler(os.path.join(datapath,'run_{}.log'.format(i)))
    runlog.setFormatter(formatter)
    logger.addHandler(runlog)
    iperf_flow.run(time=args.time, flows='all', preclean=False)
    logger.removeHandler(runlog)

ssh_node.close_consoles()

for flow in flows :
    flow.compute_ks_table(directory=datapath, title=plottitle)

# iperf_flow.plot(title=plottitle, directory=args.output_directory)

iperf_flow.close_loop()
logging.shutdown()
