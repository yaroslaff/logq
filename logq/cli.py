import re
from collections import defaultdict
from datetime import datetime
import os
import sys
import argparse
import json
from evalidate import Expr, EvalException, base_eval_model
from typing import List, Dict, Any

from .stats import stats
from .logfile import LogFile


def get_args():
    parser = argparse.ArgumentParser(description='Process nginx log file')
    parser.add_argument('path', type=str, help='Path to log file')
    parser.add_argument('--verbose', '-v', action='store_true', default=False)
    parser.add_argument('--output', '-o', choices=["sum", "json", "log", "ip"], default="sum")
    parser.add_argument('--sort', '-s', default=None, help='Sort output by given field (e.g. "hits" or "hits-" for descending order)')

    g = parser.add_argument_group('Query')
    g.add_argument('--ip-eval', '-i', type=str, default=None, help='Expression for IP summary to evaluate. Example: "status200 > 100" or "ip == \'10.0.0.254\'"')
    g.add_argument('--rec-eval', '-r', type=str, default=None, help='Expression for log record to evaluate. Example: "status==403"')


    return parser.parse_args()



def filter(logfile: LogFile, ip_eval: str, rec_eval: str, output: str) -> List[Dict[str, Any]]:
    data = list()
    my_model = base_eval_model.clone()
    my_model.nodes.extend(['Call', 'Attribute'])
    my_model.attributes.extend(['startswith', 'endswith'])

    try:
        sum_expr = Expr(ip_eval, model=my_model) if ip_eval else None
    except EvalException as e:
        print(f"Invalid expression: {e}")
        sys.exit(1)

    try:
        rec_expr = Expr(rec_eval, model=my_model) if rec_eval else None
    except EvalException as e:
        print(f"Invalid expression: {e}")
        sys.exit(1)

    for ip in logfile.ips():
        summary = logfile.summary(ip)

        try:
            match = eval(sum_expr.code, None, summary) if sum_expr else True
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
                        rec_match = eval(rec_expr.code, None, rec_data) if rec_expr else True
                    except EvalException as e:            
                        stats.rec_runtime_errors += 1
                        rec_match = False
                    if rec_match:
                        data.append(rec_data)
                        stats.rec_matches += 1
    return data

def sort_data(data: List[Dict[str, Any]], sort_order: str, output: str) -> List[Dict[str, Any]]:
    sort_field = sort_order.rstrip('-')
    print("field:", sort_field)
    sort_reverse = sort_order.endswith('-') if sort_order else False

    try:
        if output == "sum":
            data_sorted = sorted(data, key=lambda x: x[sort_field] if sort_field else x['hits'], reverse=sort_reverse)
            return data_sorted
        elif output in ["json", "log"]:
            data_sorted = sorted(data, key=lambda x: x[sort_field] if sort_field else x['datetime'], reverse=sort_reverse)
            return data_sorted
        else:
            raise NotImplementedError(f"Output format {output} not implemented in sort")
    except KeyError as e:
        print(f"Invalid sort field: {e}. Try {'/'.join(data[0].keys())}")
        sys.exit(1)



def main():

    args = get_args()
    
    log_path = args.path
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[(?P<datetime>[^\]]+)\] "(?P<method>\w+) (?P<url>[^ ]+) (?P<protocol>[^"]+)" (?P<status>\d+) (?P<size>\d+) "(?P<referrer>[^"]*)" "(?P<user_agent>[^"]*)"'
    )
    logfile = LogFile(log_path, log_pattern)
    logfile.read_all()

    if args.verbose:
        print(f"# Loaded {logfile.nrecords} records from {args.path}")


    data = filter(logfile, args.ip_eval, args.rec_eval, args.output)
            
    # Output
    data = sort_data(data, sort_order=args.sort, output=args.output)

    if args.output == "sum":
        print(json.dumps(data, indent=4))
    elif args.output in ["json", "log"]:            
        print(json.dumps(data, indent=4))
    else:
        raise NotImplementedError(f"Output format {args.output} not implemented")


    if args.verbose:
        print("# Sum IP matches:", stats.sum_matches)
        print("# Sum Name errors:", stats.sum_name_errors)
        print("# Sum Runtime errors:", stats.sum_runtime_errors)
        print("# Records matches:", stats.rec_matches)
        print("# Records Runtime errors:", stats.rec_runtime_errors)
        