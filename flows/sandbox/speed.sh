#!/bin/bash

# ctrl-c exit
trap "echo 'break and exit'; exit 2" INT

# client mode
if [ "$1" == "-c" ]
then
	# log file path
	path=./log/
	
	# touch log file using timestamp
	timestamp=$(date +'%Y-%m-%d-%H:%M:%S')
	file_name='iperf_'$timestamp'.log'
	full_name=$path$file_name
	touch $full_name
	echo "touch file : $file_name"
	
	# iperf setting
	#svr_ip='192.168.22.40'
	#svr_ip='192.168.200.90'
	#svr_ip='172.1.200.70'
	#svr_ip='192.168.1.200'
	svr_ip='10.31.0.181'
	port=''
	period='1000'
	interval='1'
	unit='m'
	bdwidth='100M'
	
	# main loop
	while true
	do 
		# record start time 
		timestamp=$(date +'%Y-%m-%d-%H:%M:%S')
		echo "time : $timestamp" | tee -a $full_name

		# iperf client start
		if [ -z "$2" ]
		then
			iperf -c $svr_ip -t $period -i $interval -f $unit -b $bdwidth | tee -a $full_name
			#iperf -c $svr_ip -t $period -i $interval >> $full_name
		else
			port=$2
			iperf -c $svr_ip -t $period -p $port -i $interval -f $unit -b $bdwidth | tee -a $full_name
		fi

		sleep 5s
	done

# server mode
elif [ "$1" == "-s" ]
then
	# iperf setting
	local_ip='192.168.200.90'
	#local_ip='192.168.22.40'
	port=''
	period='1000'
	interval='10'

	# iperf server start
	if [ -z "$2" ]
	then
		iperf -s -B $local_ip -i $interval -f $unit
	else
		port=$2
		iperf -s -B $local_ip -p $port -i $interval -f $unit
	fi
else
	echo "usage: speed [-c/-s]"
fi
