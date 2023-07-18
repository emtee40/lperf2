#!/usr/bin/env python3
#
# ---------------------------------------------------------------
# * Copyright (c) 2018
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
# Date July 2023
import shutil
import logging
import flows
import argparse
import time, datetime
import os,sys
import ssh_nodes
import gc

from flows import *
from ssh_nodes import *

parser = argparse.ArgumentParser(description='Run a bufferbloat test')
parser.add_argument('--host_a', type=str, default="192.168.1.40", required=False, help='STA host to run iperf')
parser.add_argument('--host_b', type=str, default="192.168.1.141", required=False, help='STA host to run iperf')
parser.add_argument('-i','--interval', type=int, required=False, default=1, help='iperf report interval')
parser.add_argument('-n','--runcount', type=int, required=False, default=2, help='number of runs')
parser.add_argument('-t','--time', type=float, default=10, required=False, help='time or duration to run traffic')
parser.add_argument('-o','--output_directory', type=str, required=False, default='./pyflow_log', help='output directory')
parser.add_argument('--test_name', type=str, default='tcp_cca', required=False)
parser.add_argument('--loglevel', type=str, required=False, default='INFO', help='python logging level, e.g. INFO or DEBUG')
parser.add_argument('-c','--cca', nargs="+", default=["cubic", "reno", "bbr", "bbr2", "prague"], required=False, help='set the TCP CCA list to be tested')

# Parse command line arguments
args = parser.parse_args()

# Set up logging below
logfilename='test.log'
testselect_dir = args.test_name
args.output_directory = os.path.join(args.output_directory, testselect_dir)
if not os.path.exists(args.output_directory):
    print('Making log directory {}'.format(args.output_directory))
    os.makedirs(args.output_directory)

fqlogfilename = os.path.join(args.output_directory, logfilename)
numeric_level = getattr(logging, args.loglevel.upper(), None)
if not isinstance(numeric_level, int):
    raise ValueError('Invalid log level: %s' % args.loglevel)
logging.basicConfig(filename=fqlogfilename, level=numeric_level, format='%(asctime)s %(name)s %(module)s %(levelname)-8s %(message)s')
logging.info("log file setup for {}".format(fqlogfilename), exc_info=True)
print('Writing log to {}'.format(fqlogfilename))

#configure asyncio logging
logging.getLogger('asyncio').setLevel(logging.INFO)
logger = logging.getLogger(__name__)
#loop = asyncio.get_event_loop()
#loop.set_debug(False)

#instantiate DUT host and NIC devices
dut1 = ssh_node(name='HOST_A', ipaddr=args.host_a, device='eth0', devip='192.168.1.40')
dut2 = ssh_node(name='HOST_B', ipaddr=args.host_b, device='eth0', devip='192.168.1.141')

logging.basicConfig(filename='test.log', level=logging.INFO, format='%(asctime)s %(name)s %(module)s %(levelname)-8s %(message)s')

logging.getLogger('asyncio').setLevel(logging.DEBUG)
root = logging.getLogger(__name__)
loop = asyncio.get_event_loop()
loop.set_debug(False)

ssh_node.open_consoles(silent_mode=True)

try:
    for congestion in args.cca :
        thisflow = iperf_flow(name='TCP-Flow-{}'.format(congestion), user='root', server=dut1, client=dut2, dstip=dut1.devip, proto='TCP', interval=1, debug=False, srcip=dut2.devip, srcport='6001', dstport='6001', tos='ac_vi', cca=congestion)
        gc.disable()
        iperf_flow.run(time=args.time, flows=[thisflow], epoch_sync=True)
        gc.enable()
        del thisflow
        try :
            gc.collect()
        except:
            pass

finally :
    ssh_node.close_consoles()
    iperf_flow.close_loop()
    logging.shutdown()
