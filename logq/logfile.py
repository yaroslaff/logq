from collections import defaultdict
import os

from .logrecord import LogRecord
from .utils import dhms

class LogFile:
    def __init__(self, path, log_pattern):
        self.path = path
        self.log_regex = log_pattern
        self.ip_records = defaultdict(list)
        self._offset = 0
        self._inode = None
        self.nrecords = 0

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
        return sum
