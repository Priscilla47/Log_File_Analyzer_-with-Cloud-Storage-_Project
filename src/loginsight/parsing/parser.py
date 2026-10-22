import re
from datetime import datetime

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.*?)\] "(?P<request>.*?)" (?P<status>\d{3}) (?P<size>\S+)'
)

def parse_line(line):
    match = LOG_PATTERN.match(line)
    if match:
        data = match.groupdict()
        data['time'] = datetime.strptime(data['time'].split()[0], '%d/%b/%Y:%H:%M:%S')
        data['method'], data['path'], _ = data['request'].split()
        data['status'] = int(data['status'])
        data['size'] = int(data['size']) if data['size'] != '-' else 0
        return data
    return None

def parse_file(filepath):
    entries = []
    with open(filepath) as file:
        for line in file:
            parsed = parse_line(line)
            if parsed:
                entries.append(parsed)
    return entries