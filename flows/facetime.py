#!/bin/env python3
#
# ---------------------------------------------------------------
# * Copyright (c) 2021
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
# Date December 2022
#
# Script flow to run a video and audio facetime traffic, full duplex
#
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
parser.add_argument('--host_wifi1', type=str, default="10.59.13.58", required=False, help='STA host to run iperf')
parser.add_argument('--host_wifi2', type=str, default="10.59.13.70", required=False, help='STA host to run iperf')
parser.add_argument('-i','--interval', type=int, required=False, default=1, help='iperf report interval')
parser.add_argument('-n','--runcount', type=int, required=False, default=2, help='number of runs')
parser.add_argument('-t','--time', type=float, default=10, required=False, help='time or duration to run traffic')
parser.add_argument('-o','--output_directory', type=str, required=False, default='./pyflow_log', help='output directory')
parser.add_argument('--test_name', type=str, default='facetime', required=False)
parser.add_argument('--loglevel', type=str, required=False, default='INFO', help='python logging level, e.g. INFO or DEBUG')

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
wifi1 = ssh_node(name='WiFi_A', ipaddr=args.host_wifi1, device='eth1', devip='192.168.1.58')
wifi2 = ssh_node(name='WiFi_B', ipaddr=args.host_wifi2, device='eth1', devip='192.168.1.70')

#instantiate traffic objects or flows

video=iperf_flow(name='VIDEO_FACETIME_UDP', user='root', server=wifi1, client=wifi2, dstip=wifi1.devip, proto='UDP', interval=1, debug=False, srcip=wifi2.devip, srcport='6001', dstport='6001', offered_load='30:600K',trip_times=True, tos='ac_vi', latency=True, fullduplex=True)
audio=iperf_flow(name='AUDIO_FACETIME_UDP', user='root', server=wifi1, client=wifi2, dstip=wifi1.devip, proto='UDP', interval=1, debug=False, srcip=wifi2.devip, srcport='6002', dstport='6002', offered_load='50:25K',trip_times=True, tos='ac_vo', latency=True, fullduplex=True)

ssh_node.open_consoles(silent_mode=True)

traffic_flows = iperf_flow.get_instances()
try:
    if traffic_flows:
        for runid in range(args.runcount) :
            for traffic_flow in traffic_flows:
                print("Running ({}/{}) {} traffic client={} server={} dest={} with load {} for {} seconds".format(str(runid+1), str(args.runcount), traffic_flow.proto, traffic_flow.client, traffic_flow.server, traffic_flow.dstip, traffic_flow.offered_load, args.time))
            gc.disable()
            iperf_flow.run(time=args.time, flows='all', epoch_sync=True)
            gc.enable()
            try :
                gc.collect()
            except:
                pass

        for traffic_flow in traffic_flows :
            traffic_flow.compute_ks_table(directory=args.output_directory, title=args.test_name)

    else:
        print("No traffic Flows instantiated per test {}".format(args.test_name))

finally :
    ssh_node.close_consoles()
    if traffic_flows:
        iperf_flow.close_loop()
    logging.shutdown()
