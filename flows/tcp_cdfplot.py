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

from datetime import datetime as datetime, timezone
from flows import *
from ssh_nodes import *

parser = argparse.ArgumentParser(description='Run an isochronous UDP data stream')
parser.add_argument('-s','--server', type=str, default="192.168.1.33", required=False, help='host to run iperf server')
parser.add_argument('--server_dev', type=str, default='eth0', required=False, help='server device name')
parser.add_argument('-c','--client', type=str, default="192.168.1.31", required=False, help='host to run iperf client')
parser.add_argument('--client_dev', type=str, default='eth0', required=False, help='client device name')
parser.add_argument('-d','--dstip', type=str, default="192.168.1.33",required=False, help='iperf destination ip address')
parser.add_argument('-i','--interval', type=float, required=False, default=1, help='iperf report interval')
parser.add_argument('-l','--length', type=int, required=False, default=None, help='udp payload size')
parser.add_argument('-n','--runcount', type=int, required=False, default=5, help='number of runs')
parser.add_argument('-t','--time', type=float, default=10, required=False, help='time or duration to run traffic')
parser.add_argument('-O','--offered_load', type=str, default=None, required=False, help='offered load; <fps>:<mean>,<variance>')
parser.add_argument('-T','--title', type=str, default="TCP Single Flow CDF", required=False, help='title for graphs')
parser.add_argument('--tcp_tx_delay', type=str, default='80', required=False, help='enable tcp tx delay')
parser.add_argument('-S','--tos', type=str, default='ac_be', required=False, help='type of service or access class; BE, VI, VO or BK')
parser.add_argument('-o','--output_directory', type=str, required=False, default='./data', help='output directory')
parser.add_argument('--qdisc', type=str, required=False, default='fq', help='set the tc qdisc')
parser.add_argument('--tc_bin', type=str, required=False, default='/usr/sbin/tc', help='set the tc command')
parser.add_argument('--loglevel', type=str, required=False, default='INFO', help='python logging level, e.g. INFO or DEBUG')
parser.add_argument('--chronyc', dest='chronyc', action='store_true', help='chronyc is available on duts')
parser.set_defaults(chronyc=True)

args = parser.parse_args()

logfilename='test.log'
if not os.path.exists(args.output_directory):
    print('Making log directory {}'.format(args.output_directory))
    os.makedirs(args.output_directory)

fqlogfilename = os.path.join(args.output_directory, logfilename)
print('Writing log to {}'.format(fqlogfilename))

logging.basicConfig(filename=fqlogfilename, level=logging.INFO, format='%(asctime)s %(levelname)-8s %(module)-9s  %(message)s')

logging.getLogger('asyncio').setLevel(logging.INFO)
root = logging.getLogger(__name__)
loop = asyncio.get_event_loop()
loop.set_debug(False)
ssh_node.loop.set_debug(False)
loop = asyncio.get_event_loop()

plottitle='{} {} {} {} bytes tcpdelay={} qdisc={}'.format(args.title, args.offered_load, args.tos, args.length, args.tcp_tx_delay, args.qdisc)

duta = ssh_node(name='DUTA', ipaddr=args.client, console=True, ssh_speedups=False)
dutb = ssh_node(name='DUTB', ipaddr=args.server, console=True, ssh_speedups=False)
duts = [duta, dutb]

duta.rexec(cmd='/usr/bin/uname -r'.format(args.tc_bin, args.client_dev, args.qdisc))
dutb.rexec(cmd='/usr/bin/uname -r'.format(args.tc_bin, args.client_dev, args.qdisc))
duta.rexec(cmd='/usr/local/bin/iperf -v'.format(args.tc_bin, args.client_dev, args.qdisc))
dutb.rexec(cmd='/usr/local/bin/iperf -v'.format(args.tc_bin, args.client_dev, args.qdisc))
duta.rexec(cmd='{} qdisc replace dev {} root {}'.format(args.tc_bin, args.client_dev, args.qdisc))
dutb.rexec(cmd='{} qdisc replace dev {} root {}'.format(args.tc_bin, args.server_dev, args.qdisc))
duta.rexec(cmd='{} qdisc show'.format(args.tc_bin))
dutb.rexec(cmd='{} qdisc show'.format(args.tc_bin))
if args.chronyc:
    for dut in duts :
        dut.rexec(cmd='/usr/bin/chronyc sources')
        dut.rexec(cmd='/usr/bin/chronyc tracking')

flows = [iperf_flow(name="TCP", user='root', server=dutb, client=duta, proto='TCP', offered_load=args.offered_load, interval=args.interval, dstip=args.dstip, tos=args.tos, length=args.length, latency=True, tcp_tx_delay=args.tcp_tx_delay)]

for i in range(args.runcount) :
    print("Running ({}) traffic with load {} for {} seconds".format(str(i), args.offered_load, args.time))
    iperf_flow.run(time=args.time, flows='all', preclean=False)

ssh_node.close_consoles()

for flow in flows :
    flow.compute_ks_table(directory=args.output_directory, title=plottitle)

# iperf_flow.plot(title=plottitle, directory=args.output_directory)

iperf_flow.close_loop()
logging.shutdown()
