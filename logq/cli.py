import re
from collections import defaultdict
from datetime import datetime
import os
import sys
import argparse
import json
import toml
from evalidate import Expr, EvalException, base_eval_model
from typing import List, Dict, Any

from .stats import stats
from .logfile import LogFile
from .config import settings, load_config
from .expressions import ExpressionCollection

def get_args():

    def_period = 60

    parser = argparse.ArgumentParser(description=f'Process nginx log file. Python: {sys.version_info.major}.{sys.version_info.minor}')
    parser.add_argument('-l', '--log', metavar='PATH', type=str, nargs='?', help='Path to log file')
    parser.add_argument("-c", "--config", help="Path to logq.toml")


    g = parser.add_argument_group('Output')
    g.add_argument('--verbose', '-v', action='store_true', default=False)
    g.add_argument('--output', '-o', choices=["json", "log", "ip", "rate"], default="log")    
    g.add_argument('--sort', '-s', default=None, help='Sort output by given field (e.g. "hits" or "hits-" for descending order)')
    g.add_argument('--num', '-n', default=None, type=int, help='Num results to show (for [sorted] sessions)')
    g.add_argument('--period', '-p', default=def_period, type=int, help='period for counters')
    g.add_argument('--sum', '--summary', action='store_true', default=False, help='print only session summary')


    g = parser.add_argument_group('Filters (Session > Record). Stages: onload, tagging, rate, session, out')
    g.add_argument('-q', dest='query', default=None, metavar='NAME', nargs='*', type=str, help='Run named queries NAME from config')
    # g.add_argument('-a', '--auto', choices=['no', 'tagrate', 'auto'], default='auto', type=str, help='Auto-load queries from config: no, tagrate (tagging+rate), auto (all with auto=true)')
    g.add_argument('-r', '--run', type=str, help='Run named script from config')


    g.add_argument('--onload', nargs='+', type=str, help='Add onload query expression filter(s)')
    g.add_argument('--session', nargs='+', type=str, help='Add session query expression filter(s)')
    g.add_argument('--out', nargs='+', type=str, help='Add out query expression filter(s)')

    return parser.parse_args()



def session_filter(logfile: LogFile, ec: ExpressionCollection) -> List[Dict[str, Any]]:
    iplist = list()

    # onload already applied in read_all

    # tagging pass
    for ip in logfile.ips():
        for r in logfile.ip_records[ip]:
            rec_data = r.as_dict()
            for e in ec.iter("tagging"):
                try:
                    if eval(e.code, None, rec_data):
                        logfile.add_tag(ip, e.param)
                except NameError as ex:
                    print(f"Name error in expression {e.expr}: {ex}", file=sys.stderr)
                    sys.exit(1)

    # rating pass
    for ip in logfile.ips():
        for r in logfile.ip_records[ip]:
            rec_data = r.as_dict()
            for e in ec.iter("rate"):
                rec_match = eval(e.code, None, rec_data)
                if rec_match:
                    logfile.ratecount(ip, e.param, r.datetime, data=r)
                    pass


    # session and out pass
    for ip in logfile.ips():
        summary = logfile.summary(ip)
        if ec.apply_all("session", summary) or not ec.session:
            # session summary match
            iplist.append(ip)
        #if all(eval(e.code, None, summary) for e in ec.iter("session")) or not ec.session:
        #    # session summary match
        #    iplist.append(ip)

    return iplist



def sort_sessions(data: List[Dict[str, Any]], sort_order: str, output: str) -> List[Dict[str, Any]]:
    """  Sort data by given field """

    if sort_order is not None:
        sort_field = sort_order.rstrip('-')
    else:
        sort_field = 'hits'

    sort_reverse = sort_order.endswith('-') if sort_order else False

    data_sorted = sorted(data, key=lambda x: x.get(sort_field, 0), reverse=sort_reverse)
    return data_sorted



def get_queries(args: argparse.Namespace) -> ExpressionCollection:
    """ Get queries from config and make ec """
    ec = ExpressionCollection()


    queries = args.query if args.query else list()

    if args.run:
        try:
            script = settings.scripts[args.run]
        except KeyError:
            print(f"Script {args.run!r} not found in config", file=sys.stderr)
            sys.exit(1)
                
        for qname in script['queries']:
            if qname not in settings.query:
                print(f"Error in script {args.run!r}, query {qname!r} not found in config", file=sys.stderr)
                sys.exit(1)
            queries.append(qname)
        
        # add script options
        if script.get('sort', None):
            ec.sort_field = script['sort']
        if script.get('sum', False):
            ec.summarize = True

    try:
        if queries:
            for q in queries:
                if q in settings.query:
                    qconf = settings.query[q] 

                    try:
                        stage = qconf['stage']
                        query = qconf['query']
                        param = None
                        if stage == 'tagging':
                            param = qconf['tag']
                        if stage == 'rate':
                            param = qconf['counter']

                        ec.add(query, stage, param)

                    except KeyError as e:
                        print(f"Invalid query config for {q!r}, missing key {e}")
                        sys.exit(1)

                else:
                    print(f"Query {q!r} not found in config")
                    sys.exit(1)

        if args.onload:
            for q in args.onload:
                ec.add(q, "onload", None)

        if args.session:
            for q in args.session:
                ec.add(q, "session", None)
        
        if args.out:
            for q in args.out:
                ec.add(q, "out", None)
    
    except ValueError as e:
        print(f"Error in expression: {e}")
        sys.exit(1)

    return ec

def main():

    args = get_args()
    
    load_config(args.config)

    log_path = args.log
    if not log_path:
        print("No log file specified")
        sys.exit(1)


    logconf = settings.getlogconf(log_path)

    ec = get_queries(args)

    log_pattern = re.compile(logconf['regex'])
    logfile = LogFile(log_path, log_pattern, ec=ec, period=args.period)
    logfile.read_all()

    if args.verbose:
        print(f"# Loaded {logfile.nrecords} records from {args.path}")


    iplist = session_filter(logfile, ec=ec)

    summarize = ec.summarize or args.sum

    if args.sum:
        # Output
        data = list()

        for ip in iplist:
            summary = logfile.summary(ip)
            data.append(summary)
        sort_order = ec.sort_field or args.sort
        data = sort_sessions(data, sort_order=sort_order, output=args.output)
        print(json.dumps(data, indent=4))
    else:
        if args.output == "rate":
            for ip in iplist:
                for cnt in logfile.ratecounters(ip):
                    for r in logfile.rate_records(ip, cnt):
                        print(r.raw)
                
        else:
            printed_ips = set()
            for r in logfile.all_records:
                if r.ip not in iplist:
                    continue
                rec_data = r.as_dict()
                if ec.apply_all("out", rec_data):
                    if args.output == "json":
                        print(json.dumps(rec_data, ensure_ascii=False))
                    elif args.output == "ip":
                        if r.ip not in printed_ips:
                            print(f"# {r.ip}")
                            printed_ips.add(r.ip)
                    else:   # log
                        print(r.raw)


    if args.verbose:
        print("# Sum IP matches:", stats.sum_matches)
        print("# Sum Name errors:", stats.sum_name_errors)
        print("# Sum Runtime errors:", stats.sum_runtime_errors)
        print("# Records matches:", stats.rec_matches)
        print("# Records Runtime errors:", stats.rec_runtime_errors)
        