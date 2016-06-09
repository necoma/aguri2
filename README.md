# aguri2
========
The primary aggregation tools for agurim

aguri2 is the primary aggregation tool for agurim.
aguri2 can produce aggregated flow records using the pcap library, or
reading the aguri_flow records from the standard input.
To read NetFlow or sFlow, use "aguri2_xflow" under the subdirectory.

aguri2 reopens the output file when it receives a HUP signal, which can
be used for log-rotation.

The secoundary aggregation tools and web user interface for agurim can
be found at
https://github.com/necoma/agurim/

## Install

	% make
	% sudo make install

To run aguri2 and archive its outputs, use 'scripts/agurify2.sh'.
See 'scripts/README.md' for more detail.

## Usage

	aguri2 [-Ddhv] [-c count] [-i interface] [-f pcapfilters] [-l nodes]
		[-p pidfile] [-r pcapfile] [-s interval] [-T timeoffset]
		[-t thresh] [-w outputfile]

  + `-c count`:  
    Exit after processing count packets.

  + `-D`: Disable heuristics for aggregation.
      -D disables the threshold scaling that gives bias according to
      the prefixlength for reducing the number of entries as well as
      for supressing unuseful entries for operational practices.
      -DD disables merging nodes with similar counts that mitigates
      threshold sensitivity.
      -DDD disables both heuristics.
  
  + `-d`: Enable debug outputs.
  
  + `-i interface`:  
    Listen on interface.

  + `-f pcapfilters`:  
    Specify pcap filters.

  + `-h`: Display help information and exit.

  + `-l nodes`:  
    Use the specified number of nodes for each tree.

  + `-p pidfile`:  
    Write the process id to the pidfile.

  + `-r pcapfile`:  
    Read packets from pcapfile.

  + `-s interval`:  
    Output a summary every interval seconds.

  + `-T timeoffset`:  
    Add timeoffset (integer in hour) to the localtime. This can be
    used to set the time in the output to another timezone.

  + `-t thresh`:  
    Specify the threshold value for aggregation.  The unit is 0.1%.
    Default is 10 (1%).

  + `-v`: Enable the verbose mode.

  + `-w outputfile`:  
    Direct output to outputfile.  By default, output is directed to stdout.

## Examples

To read from an interface and show output records:

	aguri -i <ifname>

To read from an interface and write the records to a file every 30
seconds:

	aguri -i <ifname> -s 30 -w <logfile>

To read a saved pcap file:

	aguri -r <pcapfile>

To read netflow data from port 2055, and produce aggregated flow
records every 60 seconds:

	aguri2_xflow -t netflow -p 2055 | aguri2 -s 60

Similary, to read sflow data from port 6343, and produce aggregated
flow records every 60 seconds: 

	aguri2_xflow -t sflow -p 6343 | aguri2 -s 60




