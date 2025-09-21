from collections import defaultdict
import os
from evalidate import base_eval_model, Expr, EvalException
import sys
import json
from datetime import datetime
from typing import Literal, List, Dict, Any

from .logrecord import LogRecord
from .utils import dhms
from .ratecount import RateCount
from .expressions import ExpressionCollection

class LogFile:
    def __init__(self, path, log_pattern, ec: ExpressionCollection | None = None, period: int = 60):
        self.path = path
        self.log_regex = log_pattern
        self.ip_records = defaultdict(list)
        self.all_records = list()
        self.tags = defaultdict(set)
        self.ratecounts: Dict[str, Dict[str, RateCount]] = dict()
        self._offset = 0
        self._inode = None
        self.nrecords = 0
        self.period = period
        self.ec = ec


    def add_tag(self, ip, tag):
        self.tags[ip].add(tag)

    def ratecount(self, ip, tag: str, dt: datetime, data: Any = None):
        if ip not in self.ratecounts:
            self.ratecounts[ip] = dict()
        if tag not in self.ratecounts[ip]:
            self.ratecounts[ip][tag] = RateCount(self.period)
        
        self.ratecounts[ip][tag].add(dt, data=data)

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
                    if self.ec and self.ec.onload:                        
                        if all(eval(e.code, None, record_dict) for e in self.ec.iter("onload")):
                            self.ip_records[record.ip].append(record)
                            self.all_records.append(record)
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
                sum[f'rates_{counter}'] = self.ratecounts[ip][counter].get_max()
                sum[f'rates_{counter}_time'] = self.ratecounts[ip][counter].get_max_time().strftime("%d/%b/%Y %H:%M:%S")
        
            
        return sum

    def ratecounters(self, ip: str) -> List[str]:
        if ip in self.ratecounts:
            return list(self.ratecounts[ip].keys())
        return list()
    
    def rate_records(self, ip: str, tag: str) -> List[Any]:
        if ip in self.ratecounts and tag in self.ratecounts[ip]:            
            return list(self.ratecounts[ip][tag].top_dataq)
        return list()