# agurify2.sh
========
A script to archive aguri2 log files.

agurify2.sh is a script to be invoked by a cron job to run aguri2 and
and archive its logs.

If aguri2 is not running, the script executes the aguri2 program and
exits.  Otherwise, it archives the log, and sends the HUP signal to
aguri2 for re-opning the log file.
The log is archived using a filename based on the first StartTime in
the log.

Note for setting the interval:
The smaller the interval is, the finer the data resoluton becomes.
However, it incurs more overhead for re-aggregation.
Also, daily summaries are created from primary summaries with 300
second resolution.  So, set the interval appropriate to make 300
second resolution.  30, 60 or 300 is recommended.  If you have enough
traffic to make 30-second-long summaries, set it to 30.

Note for setting the invocation interval:
There are trade-offs on how to select the invocaton interval of cron
job.
The invocation interval should be larger than the interval set by the
'-s' option, and smaller than 60 minutes (to make hourly summaries).
The advantages for a smaller interval are (1) shorter delay for the
Web UI and (2) shorter delay for failure recovery.
The Web user interface uses the archived datasets so that, if the
datasets are directly referenced by the Web UI, the archive interval
bounds the lag for the latest dataset.
The script can re-invoke aguri2 after aguri2 failed so that the
invocation interval bounds the lag for re-invoation after a failure.
The disadvantages are overheads of re-aggregation for daily summaries,
or fine-grained plots requested by the Web UI.
The recommended invocation interval is 5, 10, 15, 20, 30 or 60
minutes. Select 10 minutes for busy traffic and 60 minutes for low
traffic.

## Usage

To read from pcap, run this script from cron(8) every 10 minutes:

	agurify2.sh -i <ifname> [-d logdir] [-s interval] [-f pidfile]

To read from a socket for NetFlow or sFlow:

	agurify2.sh -t netflow|sflow [-p port] [-d logdir] [-s interval] [-f pidfile]

  + `-i interface`:  
    Listen on interface using BPF.

  + `-d logdir`:
    Specify the log directory.  The logs are archived under this directory.
  
  + `-f pidfile`:  
    Specify the pid file.  If not specified, "aguri2.pid" is created
    under the log directory.

  + `-p port`:  
    Listen on the port for NetFlow or sFlow exports.

  + `-s interval`:  
    Output a summary every interval seconds.

  + `-t netflow|sflow`:  
    Specify the flow type, either 'netflow' or 'sflow'.

## Examples

To run agurify2.sh for netflow, and archive logs every 10 minutes,
set the following entry in the crontab, assuming 'datadir=/export/aguri2' and 'interval=60':

	*/10 * * * * /script_path/agurify2.sh -t netflow -p 2055 -d /export/aguri2 -s 60 2>&1

Similary, for reading from interface 'em0' using pcap,

	*/10 * * * * /script_path/agurify2.sh -i em0 -d /export/aguri2 -s 60 2>&1
