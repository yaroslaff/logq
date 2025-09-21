from datetime import datetime

class LogRecord:
    def __init__(self, line, log_regex):
        m = log_regex.match(line)
        if not m:
            raise ValueError(f'Invalid log line: {line}')
        self.ip = m.group('ip')
        self.datetime_str = m.group('datetime')
        self.datetime = datetime.strptime(self.datetime_str.split()[0], "%d/%b/%Y:%H:%M:%S")
        self.method = m.group('method')
        self.uri = m.group('uri')
        self.protocol = m.group('protocol')
        self.status = int(m.group('status'))
        self.size = int(m.group('size'))
        self.referrer = m.group('referrer')
        self.user_agent = m.group('user_agent')
        self.raw = line

    def as_dict(self):
        return {
            'ip': self.ip,
            'datetime': self.datetime.strftime("%d/%b/%Y %H:%M:%S"),
            'method': self.method,
            'uri': self.uri,
            'protocol': self.protocol,
            'status': self.status,
            'size': self.size,
            'referrer': self.referrer,
            'user_agent': self.user_agent,
            'raw': self.raw
        }