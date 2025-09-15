# LogQ
Anomaly (hacking attempt) detector for webserver log files (work in progress, usable only for developers)

example command:
~~~
logq -q post logintag realuser -l /tmp/access.log -s rates:postrate
~~~

## Examples
### Per-IP summary
~~~bash
logq /tmp/access.log 
[
    {
        "ip": "15.169.132.123",
        "hits": 202,
        "first": "01/Sep/2025 16:16:27",
        "last": "01/Sep/2025 17:57:55",
        "duration": "1h 41m 28s",
        "duration_sec": 6088,
        "status302": 17,
        "status200": 179,
        "status206": 6
    },
    # many records like this
]

# Who has most 404 hits?
logq /tmp/access.log  -s status404

# same but only for settions with duration over 1h
logq /tmp/access.log  -s status404 -i 'duration_sec>3600'

# print only IPs:
logq /tmp/access.log  -s status404 -i 'duration_sec>3600' -o ip
166.29.193.63
31.24.114.169
...
~~~

### Log records

Use `-o json` or `-o log` 
~~~

~~~