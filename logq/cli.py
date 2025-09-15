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

def get_args():
    parser = argparse.ArgumentParser(description='Process nginx log file')
    parser.add_argument('-l', '--log', metavar='PATH', type=str, nargs='?', help='Path to log file')
    parser.add_argument("-c", "--config", help="Path to logq.toml")
    parser.add_argument('--verbose', '-v', action='store_true', default=False)
    parser.add_argument('--output', '-o', choices=["sum", "json", "log", "ip"], default="sum")
    parser.add_argument('--sort', '-s', default=None, help='Sort output by given field (e.g. "hits" or "hits-" for descending order)')
    parser.add_argument('--num', '-n', default=None, type=int, help='Num results to show (for [sorted] sessions)')
    parser.add_argument('--query', '-q', default=None, metavar='NAME', nargs='*', type=str, help='Run queries NAME from config')

    g = parser.add_argument_group('Filters (Session > Record)')
    g.add_argument('--record', '-r', type=str, default=None, help='Record filter (for -o json/log). Expression for log record to evaluate. Example: "status==403"')


    return parser.parse_args()



def filter(logfile: LogFile, tagexpr: dict, rateexpr: dict,  q_session: str, q_records: str, output: str) -> List[Dict[str, Any]]:
    data = list()
    my_model = base_eval_model.clone()
    my_model.nodes.extend(['Call', 'Attribute'])
    my_model.attributes.extend(['startswith', 'endswith'])

    tagcode = dict()
    ratecode = dict()

    for tag, expr in tagexpr.items():
        tagcode[tag] = Expr(expr, model=my_model).code

    for counter, expr in rateexpr.items():
        ratecode[counter] = Expr(expr, model=my_model).code

    try:
        session_expr = Expr(q_session, model=my_model) if q_session else None
    except EvalException as e:
        print(f"Invalid expression: {e}")
        sys.exit(1)


    try:
        record_expr = Expr(q_records, model=my_model) if q_records else None
    except EvalException as e:
        print(f"Invalid expression: {e}")
        sys.exit(1)


    # tagging pass
    for ip in logfile.ips():
        for r in logfile.ip_records[ip]:
            rec_data = r.as_dict()
            try:
                for tag, code in tagcode.items():
                    rec_match = eval(code, None, rec_data)
                    if rec_match:
                        logfile.add_tag(ip, tag)
                        pass


            except EvalException as e:
                print(e, file=sys.stderr)
                sys.exit(1)
                pass

    # rating pass
    for ip in logfile.ips():
        for r in logfile.ip_records[ip]:
            rec_data = r.as_dict()
            try:
                for counter, code in ratecode.items():
                    rec_match = eval(code, None, rec_data)
                    if rec_match:
                        logfile.ratecount(ip, counter, r.datetime)
                        pass


            except EvalException as e:
                print(e, file=sys.stderr)
                sys.exit(1)
                pass



    for ip in logfile.ips():
        summary = logfile.summary(ip)

        try:
            match = eval(session_expr.code, None, summary) if session_expr else True
        except NameError as e:
            stats.sum_name_errors += 1
            match = False
        except EvalException as e:            
            stats.sum_runtime_errors += 1
            match = False
            
        if match:
            stats.sum_matches += 1
            if output in ["sum", "ip"]:
                data.append(summary)
            elif output in ["json", "log"]:
                for r in logfile.ip_records[ip]:
                    rec_data = r.as_dict()
                    try:
                        rec_match = eval(record_expr.code, None, rec_data) if record_expr else True
                    except EvalException as e:            
                        stats.rec_runtime_errors += 1
                        rec_match = False
                    if rec_match:
                        data.append(rec_data)
                        stats.rec_matches += 1
    return data

def sort_data(data: List[Dict[str, Any]], sort_order: str, output: str) -> List[Dict[str, Any]]:
    
    if sort_order is not None:
        sort_field = sort_order.rstrip('-')
    else:
        if output in ['sum', 'ip']:
            sort_field = 'hits'
        else:
            sort_field = 'datetime'

    sort_reverse = sort_order.endswith('-') if sort_order else False

    if output in ["sum", "ip"]:        
        data_sorted = sorted(data, key=lambda x: x.get(sort_field, 0), reverse=sort_reverse)
        return data_sorted
    elif output in ["json", "log"]:
        try:
            data_sorted = sorted(data, key=lambda x: x[sort_field], reverse=sort_reverse)
            return data_sorted
        except KeyError as e:
            print(f"Invalid sort field: {e}. Try {'/'.join(data[0].keys())}")
            sys.exit(1)
    else:
        raise NotImplementedError(f"Output format {output} not implemented in sort")



def get_queries(queries: list):
    q_onload = None
    tagexpr = dict()
    rateexpr = dict()
    q_session = None
    q_records = None
    

    if queries:
        for q in queries:
            if q in settings.query:
                qconf = settings.query[q] 
                tag = None               
                counter = None

                try:
                    stage = qconf['stage']
                    query = qconf['query']
                    if stage == 'tagging':
                        tag = qconf['tag']
                    if stage == 'rate':
                        counter = qconf['counter']
                except KeyError as e:
                    print(f"Invalid query config for {q!r}, missing key {e}")
                    sys.exit(1)

                match stage:
                    case "onload": 
                        q_onload = query
                    case "tagging": 
                        tagexpr[tag] = query
                    case "rate":                         
                        rateexpr[counter] = query
                    case "session":
                        q_session = query
                    case "records":
                        q_records = query                    
                    case _:
                        print(f"Invalid query config: {qconf}, do not know stage {qconf['stage']!r}")
                        sys.exit(1)
                
            else:
                print(f"Query {q!r} not found in config")
                sys.exit(1)

    return q_onload, tagexpr, rateexpr, q_session, q_records

def main():

    args = get_args()
    
    load_config(args.config)

    log_path = args.log
    if not log_path:
        print("No log file specified")
        sys.exit(1)


    logconf = settings.getlogconf(log_path)

    q_onload, tagexpr, rateexpr, q_session, q_records = get_queries(args.query)

    if args.record:
        # override record filter
        q_records = args.record


    log_pattern = re.compile(logconf['regex'])
    logfile = LogFile(log_path, log_pattern, onload_expr=q_onload)
    logfile.read_all()

    if args.verbose:
        print(f"# Loaded {logfile.nrecords} records from {args.path}")

    data = filter(logfile, tagexpr=tagexpr, rateexpr=rateexpr, q_session=q_session, q_records=q_records, output=args.output)
            
    # Output
    data = sort_data(data, sort_order=args.sort, output=args.output)

    if args.output == "sum":
        print(json.dumps(data, indent=4))
    elif args.output == "ip":
        for r in data:
            print(r['ip'])
    elif args.output in ["json", "log"]:            
        if args.output == "json":
            print(json.dumps(data, indent=4))
        else:
            for r in data:
                print(r["raw"])
    else:
        raise NotImplementedError(f"Output format {args.output!r} not implemented")


    if args.verbose:
        print("# Sum IP matches:", stats.sum_matches)
        print("# Sum Name errors:", stats.sum_name_errors)
        print("# Sum Runtime errors:", stats.sum_runtime_errors)
        print("# Records matches:", stats.rec_matches)
        print("# Records Runtime errors:", stats.rec_runtime_errors)
        