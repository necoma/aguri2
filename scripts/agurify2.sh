#!/bin/sh
#
# a script to archive aguri2 log files:
# to read from pcap, run this script from cron(8) every 10 minutes.
#   agurify2.sh -i <ifname> [-d logdir] [-s interval] [-f pidfile]
# to read from a socket for NetFlow or sFlow
#   agurify2.sh -t netflow|sflow [-p port] [-d logdir] [-s interval] [-f pidfile]
# note for setting the interval:  daily summaries are created from
# primary summaries with 300 second resolution.  So, set the interval
# appropriate to make 300 second resolution.  30, 60 or 300 is recommended.
#

logdir="/export/aguri2"	# log directory
aguri2="/usr/local/bin/aguri2"	# aguri2 program
aguri2_xflow="/usr/local/bin/aguri2_xflow"	# aguri2_xflow program
interval="30"	# make summary every 30 seconds.  use 30, 60, or 300.

#
# usually, you don't need to edit below this line
#
pidfile=""	# pid file
tmpfile="tmp.agr"
logfile="log.agr"
interface=""	# interface name for reading from pcap
flowtype="" 	# 'netflow' or 'sflow'
port="6343"	# port number for socket, e.g., 6343

umask 022

# process arguments
while getopts "d:f:i:p:s:t:" opt; do
    case $opt in
	"d" ) logdir="$OPTARG" ;;
	"f" ) pidfile="$OPTARG" ;;
	"i" ) interface="$OPTARG" ;;
	"p" ) port="$OPTARG" ;;
	"s" ) interval="$OPTARG" ;;
	"t" ) flowtype="$OPTARG" ;;
	* ) echo "Usage: agurify2.sh [-i ifname] [-t netflow|sflow] [-d logdir] [-p port] [-s interval]" 1>&2
	    exit 1 ;;
    esac
done

if [ "X${pidfile}" = "X" ]; then
    pidfile="${logdir}/aguri2.pid"  # put pid file under logdir
fi

if [ -d "${logdir}" ]; then
    # cd ${logdir}	# cd to the log dir
    :
else
    echo "log dir: ${logdir} does not exist" 1>&2
    exit 1;
fi

#
# check if aguri2 is already running
running=""
if [ -r "${pidfile}" ]; then
    read pid junk < ${pidfile}

    if kill -0 ${pid} 2>/dev/null; then
	# aguri2 is running
	sleep 2		# wait a bit for finishing summary output
        # rename the log file, and send SIGHUP to aguri2 for reopening the file
	mv -f ${logdir}/${logfile} ${logdir}/${tmpfile}
 	kill -HUP ${pid}
	sleep 2
	running="YES"
    fi
fi

#
# if the program isn't running, run it and then exit.
#
if [ "X${running}" = "X" ]; then
    # aguri2 is not running, run it in background
    # first, remove the stale dump file, if any
    if [ -f "${logdir}/${logfile}" ]; then
	rm -f "${logdir}/${logfile}"
    fi

    # setup the command to execute
    if [ "X${flowtype}" = "X" ]; then
	cmd="${aguri2} -w ${logdir}/${logfile} -i ${interface} -s ${interval} -p ${pidfile}"
    else
	# use aguri2_xflow to read netflow or sflow
	cmd="${aguri2_xflow} -t ${flowtype} -p ${port} | ${aguri2} -w ${logdir}/${logfile} -s ${interval} -p ${pidfile}"
    fi

    # run the command in background, and then, exit
    echo "exec cmd: ${cmd}" 1>&2
    eval "${cmd} &>/dev/null &"
    exit $?
fi

#
# aguri2 is running, archive the log file
#
# first, extract StartTime from the log to make its file name
#   regexp to extract YYYY mm dd HH MM SS from a StartTime line
#    e.g., "%%StartTime: Fri Mar 13 00:01:02 2015 (2015/03/13 00:01:02)"
#
re='^\([^(]*(\)\([0-9]\{4\}\)/\([0-9]\{2\}\)/\([0-9]\{2\}\) \([0-9]\{2\}\):\([0-9]\{2\}\):\([0-9]\{2\}\)\().*\)'

replace="\2 \3 \4 \5 \6 \7"

timestamp=$(grep -m1 '^%%Start' ${logdir}/${tmpfile} | sed -e "s;${re};${replace};")

set -- ${timestamp} # set the time components to the position params
year=$1
month=$2
day=$3
hour=$4
min=$5
sec=$6

filename="${year}${month}${day}.${hour}${min}${sec}.agr"

echo "moving ${logdir}/${tmpfile} to ${logdir}/${year}${month}/${year}${month}${day}/${filename}" 1>&2

mkdir -p -m 775 ${logdir}/${year}${month}
mkdir -p -m 775 ${logdir}/${year}${month}/${year}${month}${day}
mv -f ${logdir}/${tmpfile} ${logdir}/${year}${month}/${year}${month}${day}/${filename}

exit 0
