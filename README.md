# Bind query log statistics generator

Produces a variety of statistics from one or more query logs passed on the command line.

# Usage:
<pre>
$ ./bind_stats.py -h
usage: bind_stats.py [-h] [--trusted [filename]] [--count [number]]
                     [--starttime [%d-%m-%y %H:%M:%S]]
                     [--endtime [%d-%m-%y %H:%M:%S]] [--querylen [number]]
                     [--topclientqry [number]]
                     filename [filename ...]

BIND's log query analyser

positional arguments:
  filename              List of BIND log files

optional arguments:
  -h, --help            show this help message and exit
  --trusted [filename]  List of trusted domains to be excluded from stats
  --count [number]      Number of queries to display, default 10
  --starttime [%d-%m-%y %H:%M:%S]
                        Analysis start time. Format %d-%m-%y %H:%M:%S
  --endtime [%d-%m-%y %H:%M:%S]
                        Analysis end time. Format %d-%m-%y %H:%M:%S
  --querylen [number]   Analyze queries longer than <number>
  --topclientqry [number]
                        Print all DNS queries for top <number> active IP's
</pre>

# Sample Output:

$ ./bind_stats.py bind.log.0
<pre>
Processing file bind.log.0

 Generating stats... 

Summary for 16-08-2018 00:47:55 - 17-08-2018 14:08:47

Total DNS QUERIES processed : 154700                   
  A      records requested : 102236
  AAAA   records requested : 52376
  SRV    records requested : 75
  TXT    records requested : 13

Top 10 DNS names requested (short name: count):
  ntp.org: 54135
  microsoft.com: 12914
  google.com: 12605
  ...

Top 10 DNS names requested (full query name: count):
  2.debian.pool.ntp.org: 13440
  1.debian.pool.ntp.org: 13437
  3.debian.pool.ntp.org: 13434
  ...
  
Top 10 DNS clients:
 10.0.10.125 : 54313
 10.0.10.162 : 24698
 10.0.10.71 : 14843
 ...
</pre>
