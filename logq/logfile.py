from collections import defaultdict
import os
from evalidate import base_eval_model, Expr, EvalException
import sys
import json
from datetime import datetime

from .logrecord import LogRecord
from .utils import dhms
from .ratecount import RateCount

class LogFile:
    def __init__(self, path, log_pattern, onload_expr: str | None = None, period: int = 60):
        self.path = path
        self.log_regex = log_pattern
        self.ip_records = defaultdict(list)
        self.tags = defaultdict(set)
        self.ratecounts = dict()
        self._offset = 0
        self._inode = None
        self.nrecords = 0
        self.onload_code = None
        self.onload_expr = onload_expr
        self.period = period

        my_model = base_eval_model.clone()
        my_model.nodes.extend(['Call', 'Attribute'])
        my_model.attributes.extend(['startswith', 'endswith'])

        try:
            self.onload_code = Expr(onload_expr, model=my_model) if onload_expr else None
        except EvalException as e:
            print(f"Invalid expression: {e}")
            sys.exit(1)


    def add_tag(self, ip, tag):
        self.tags[ip].add(tag)

    def ratecount(self, ip, tag: str, dt: datetime):
        if ip not in self.ratecounts:
            self.ratecounts[ip] = dict()
        if tag not in self.ratecounts[ip]:
            self.ratecounts[ip][tag] = RateCount(self.period)
        
        self.ratecounts[ip][tag].add(dt)

    def parse_line(self, line):
        try:
            return LogRecord(line, self.log_regex)
        except Exception:
            return None

    def read_all(self):
        self.ip_records.clear()
        self._offset = 0
        with open(self.path, 'r', encoding='utf-8') as f:
            self._inode = self._get_inode(f)
            for line in f:
                record = self.parse_line(line.strip())
                if record:

                    record_dict = record.as_dict()

                    # maybe filter?
                    if self.onload_code:
                        try:
                            match = eval(self.onload_code.code, None, record_dict)
                        except (NameError, EvalException) as e:
                            print(f"Error({type(e).__name__}): {e}")
                            print(f"Expression: {self.onload_expr}")
                            print(f"Data:")
                            print(json.dumps(record_dict, indent=2, ensure_ascii=False))
                            sys.exit(1)

                        if not match:
                            continue                    

                    self.ip_records[record.ip].append(record)
                    self.nrecords += 1
            self._offset = f.tell()

    def read_new(self):
        with open(self.path, 'r', encoding='utf-8') as f:
            inode = self._get_inode(f)
            if self._inode is not None and inode != self._inode:
                self.read_all()
                return
            f.seek(self._offset)
            for line in f:
                record = self.parse_line(line.strip())
                if record:
                    self.ip_records[record.ip].append(record)
                    self.nrecords += 1
            self._offset = f.tell()
            self._inode = inode

    def _get_inode(self, f):
        try:
            return os.fstat(f.fileno()).st_ino
        except Exception:
            return None

    def ips(self):
        return sorted(self.ip_records.keys())

    def summary(self, ip: str) -> dict:
        sum = dict()
        status=defaultdict(int)
        sum['ip'] = ip
        sum['hits'] = 0
        

        times = sorted(r.datetime for r in self.ip_records[ip])
        duration = int((times[-1] - times[0]).total_seconds())
        sum['first'] = times[0].strftime("%d/%b/%Y %H:%M:%S")
        sum['last'] = times[-1].strftime("%d/%b/%Y %H:%M:%S")
        sum['duration'] = dhms(duration)
        sum['duration_sec'] = duration

        for r in self.ip_records[ip]:
            status[f'status{r.status}'] += 1
            sum['hits'] += 1

        # merge data from status to sum
        sum.update(status)

        sum['tags'] = list(self.tags[ip])

        if ip in self.ratecounts:
            for counter in self.ratecounts[ip]:            
                sum[f'rates:{counter}'] = self.ratecounts[ip][counter].get_max()
                sum[f'rates:{counter}_time'] = self.ratecounts[ip][counter].get_max_time().strftime("%d/%b/%Y %H:%M:%S")
        
            
        return sum
