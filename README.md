# aguri2
The primary aggregation tools for agurim

aguri2 is the primary aggregation tool for agurim.
aguri2 can produce aggregated flow records using the pcap library, or
reading the aguri_flow records from the standard input.
To read NetFlow or sFlow, use "aguri2_xflow" under the subdirectory.

The secoundary aggregation tools and web user interface for agurim can
be found at
https://github.com/necoma/agurim/

HOW TO USE

	To read from an interface and show output records:
		aguri -i ifname

	To read from an interface and write the records to a file
	every 30 seconds:
		aguri -i ifname -s 30 -w logfile

	To read a saved pcap file:
		aguri -r pcapfile

	To read netflow data from port 2055, and produce aggregated
	flow records every 60 seconds:
		aguri2_xflow -t netflow -p 2055 | aguri2 -s 60

	Similary, to read sflow data from port 6343, and produce
	aggregated flow records every 60 seconds:
		aguri2_xflow -t sflow -p 6343 | aguri2 -s 60




