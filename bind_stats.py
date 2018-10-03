#!/usr/bin/env python
# Program: bind-query-log-statistics.py
# Author: Matty < matty91 at gmail dot com >
# Current Version: 1.1
# Last Updated: 01-18-2018
# Version history:
#   1.1 First attempt to normalize query log formats
#   1.0 Initial Release
# Purpose: Analyzes Bind query logs and produces a variety of query statistics.
# License: 
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  GNU General Public License for more details.


import sys
import argparse
import re
from datetime import datetime
# import socket
from collections import Counter
from collections import defaultdict
import locale
locale.setlocale(locale.LC_TIME, "en_US.UTF-8")


COUNT = 0
time_short = "%d-%m-%Y %H:%M:%S"
time_long = "%d-%b-%Y %H:%M:%S"
#TRUSTED DOMAINS
TRUSTED_DOMAINS = []

LOG_START_TIME = ""
LOG_END_TIME = ""
ANALYSIS_START_TIME = ""
ANALYSIS_END_TIME = ""
LOGFILES = []
QUERIES =[]
LONGEST_QUERIES = []
QUERY_LEN_TO_ANALYSE = 0

#DICTS
TOTAL_QUERIES = 0
DNS_QUERIES = defaultdict(int)
DNS_QUERIES_SHORT = defaultdict(int)
DNS_CLIENTS = defaultdict(int)
DNS_RECORDS = defaultdict(int)
CLIENT_QUERIES = defaultdict(lambda: defaultdict(int))
DNS_QUERY_LENGTH_CLIENT = defaultdict(lambda: defaultdict(int))

DNS_QUERY_LENGTH = defaultdict(lambda: defaultdict(lambda: defaultdict(int)))


def convert_time_format(input_time, time_format):
    time_split = input_time.split('.')
    time_dt = datetime.strptime(time_split[0], time_format)
    return time_dt


def log_time_boundaries():
    global LOG_START_TIME, LOG_END_TIME

    LOG_START_TIME = convert_time_format(QUERIES[0][0], time_long)
    LOG_END_TIME = convert_time_format(QUERIES[-1][0], time_long)


def log_time_frame_analysis():
    global ANALYSIS_START_TIME, ANALYSIS_END_TIME
    global LOG_START_TIME, LOG_END_TIME

    if ANALYSIS_START_TIME == "":
        ANALYSIS_START_TIME = LOG_START_TIME
    else:
        ANALYSIS_START_TIME = convert_time_format((ANALYSIS_START_TIME[0]), time_short)
    if ANALYSIS_END_TIME == "":
        ANALYSIS_END_TIME = LOG_END_TIME
    else:
        ANALYSIS_END_TIME = convert_time_format(ANALYSIS_END_TIME[0], time_short)


def generate_human_friendly_vars(query):
    timestamp = query[0]
    client_ip = query[1].split('#')[0]
    dns_question = query[2]
    dns_question_chopped = dns_question.split('.')
    dns_question_short = dns_question_chopped[-2] + '.' + dns_question_chopped[-1]
    dns_question_length = len(dns_question)
    record = query[4]
    return timestamp, client_ip, dns_question, dns_question_short, dns_question_length, record


def generate_stats(QUERIES):
    print("\n Generating stats... ")
    global TOTAL_QUERIES
    for query in QUERIES:
        timestamp, client_ip, dns_question, dns_question_short, dns_question_length, record = generate_human_friendly_vars(query)
        timestamp_split = timestamp.split('.')
        timestamp_short = datetime.strptime(timestamp_split[0], "%d-%b-%Y %H:%M:%S")
        if (ANALYSIS_START_TIME <= timestamp_short <= ANALYSIS_END_TIME) and (dns_question_short not in TRUSTED_DOMAINS) and (dns_question not in TRUSTED_DOMAINS):
            TOTAL_QUERIES += 1
            DNS_QUERIES[dns_question] += 1
            DNS_QUERIES_SHORT[dns_question_short] += 1
            DNS_CLIENTS[client_ip] += 1
            DNS_RECORDS[record] += 1
            CLIENT_QUERIES[client_ip][dns_question] += 1
            DNS_QUERY_LENGTH_CLIENT[dns_question_length][client_ip] += 1
            DNS_QUERY_LENGTH[dns_question_length][dns_question][client_ip] += 1


def sort_database():
    global QUERIES
    QUERIES = sorted(QUERIES, key=lambda x: x[0])


def process_query(query):
    """
    Process log query, strip redundant data and push it to an array
    """
    chopped_query = []
    hex_id = re.compile(r'@[x0-9a-h]+ ')            # match '@0x7fb1e80c6fc0 '
    strip = ["client", hex_id, "query:", "info:", "view:", "standard:", "queries:"]
    for word in query.split():
        if word not in strip:
            chopped_query.append(word)
    chopped_query[0:2] = [' '.join(chopped_query[0:2])]
    QUERIES.append(chopped_query)


def process_log(logs):
    for log in logs:
        print("Processing file " + log)
        try:
            with open(log, 'r') as fh:
                for query in fh:
                    process_query(query)
        except IOError:
            print("Error processing file " + log)
            sys.exit(1)


def process_trusted(trusted):
    global TRUSTED_DOMAINS
    print("Processing trusted domains... ")
    try:
        with open(trusted, 'r') as fh:
            for domain in fh:
                TRUSTED_DOMAINS.append(domain.strip())
    except IOError:
        print("Error processing file " + trusted)


def process_cli():
    parser = argparse.ArgumentParser(description="BIND's log query analyser")
    parser.add_argument('logfiles', nargs='+', help="List of BIND log files", metavar="filename")
    parser.add_argument('--trusted', nargs='?', help="List of trusted domains to be excluded from stats", metavar="filename" )
    parser.add_argument('--count', nargs='?', type=int, help="Number of queries to display, default 10", metavar="number", default=10)
    parser.add_argument('--starttime', nargs='?', help="Analysis start time. Format %%d-%%m-%%y %%H:%%M:%%S", metavar="%d-%m-%y %H:%M:%S", default="")
    parser.add_argument('--endtime', nargs='?', help="Analysis end time. Format %%d-%%m-%%y %%H:%%M:%%S", metavar="%d-%m-%y %H:%M:%S", default="")
    parser.add_argument('--querylen', nargs='?', type=int, metavar="number", help="Analyze queries longer than <number>")
    parser.add_argument('--topclientqry', nargs='?', type=int, metavar="number", help="Print all DNS queries for top <number> active IP's", default=0)

    args = parser.parse_args()
    return args.logfiles, args.starttime, args.endtime, args.trusted, args.count, args.querylen, args.topclientqry

def print_quick_stats():
    """ Print a number of summary statistics """
    print("\nSummary for %s - %s\n" % (datetime.strftime(ANALYSIS_START_TIME, time_short), datetime.strftime(ANALYSIS_END_TIME, time_short)))
    print("%-25s : %d" % ("Total DNS QUERIES processed", TOTAL_QUERIES))

    for record, query_count in sorted(DNS_RECORDS.items(), key=lambda a: a[1], reverse=True):
        print("  %-6s records requested : %d" % (record, query_count))


def print_top_dns_queries_short(count):
    print("\nTop {} DNS names requested (short name):".format(count))
    for query, _ in Counter(DNS_QUERIES_SHORT).most_common(count):
        print("  " + query + " : " + str(DNS_QUERIES_SHORT[query]))


def print_top_dns_queries_long(count):
    print("\nTop {} DNS names requested (full query name):".format(count))
    for query, _ in Counter(DNS_QUERIES).most_common(count):
        print("  " + query + " : " + str(DNS_QUERIES[query]))


def print_top_dns_cliens(count):
    print("\nTop {} DNS clients:".format(count))
    for client_ip, num_queries  in Counter(DNS_CLIENTS).most_common(count):
        print(" {} : {}".format(client_ip, num_queries))


def print_top_longest_domains(count):
    global LONGEST_QUERIES

    print("\nTop {} longest domains:\n".format(count))
    LONGEST_QUERIES = sorted(QUERIES, key=lambda d: len(d[2]), reverse=True)
    for i in range(0, count):
        print(" {:02}. {} ({} chars)".format(i+1, LONGEST_QUERIES[i][2], len(LONGEST_QUERIES[i][2])))


def print_dns_resolution_longer_than(qlta):
    print("\n DNS resolution for queries longer than {} characters: ".format(qlta))
    for query_length in sorted(DNS_QUERY_LENGTH.keys(), reverse=True):
        if query_length >= qlta:
            print("\n query length: {}".format(query_length))
            for query in DNS_QUERY_LENGTH[query_length]:
                print("  {}".format(query))
                for ip in DNS_QUERY_LENGTH[query_length][query]:
                    print(" IP: {}".format(ip))


def print_client_asking_long_questions(qlta=0):
    print("\n DNS questions longer than {} asked by clients(IP): ".format(qlta))
    for query_length in sorted(DNS_QUERY_LENGTH_CLIENT.keys(), reverse=True):
        if query_length >= qlta:
            print("\n query length: {}".format(query_length))
            for ip in DNS_QUERY_LENGTH_CLIENT[query_length]:
                print("  --> {}".format(ip))


def print_most_active_clients_resolutions(count):
    print("\n Print DNS queries for top {} most active clients: \n".format(count))
    for client, _ in Counter(CLIENT_QUERIES).most_common(count):
        print("\n queries for ip: ".format(client))
        for domain in CLIENT_QUERIES[client]:
            print("    -> {}".format(domain))


def print_stats():
    print_quick_stats()
    print_top_dns_queries_short(COUNT)
    print_top_dns_queries_long(COUNT)
    print_top_dns_cliens(COUNT)
    print_top_longest_domains(COUNT)

    if QUERY_LEN_TO_ANALYSE:
        print_dns_resolution_longer_than(QUERY_LEN_TO_ANALYSE)
        print_client_asking_long_questions(QUERY_LEN_TO_ANALYSE)

    if TOP_CLIENT_QRY:
        print_most_active_clients_resolutions(1)


def print_trusted_domains():
    print("\nIgnoring trusted domains...")
    print(', '.join(str(d) for d in TRUSTED_DOMAINS))

if __name__ =="__main__":

    (LOGFILES, ANALYSIS_START_TIME, ANALYSIS_END_TIME, TRUSTED, COUNT, QUERY_LEN_TO_ANALYSE, TOP_CLIENT_QRY) = process_cli()

    if not LOGFILES:
        print("At least one log file needs to be specified")
        sys.exit(1)

    process_log(LOGFILES)
    if TRUSTED:
        process_trusted(TRUSTED)
        print_trusted_domains()
    sort_database()
    log_time_boundaries()
    log_time_frame_analysis()
    generate_stats(QUERIES)
    print_stats()
