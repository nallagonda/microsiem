import csv
import io
import random
from datetime import datetime, timedelta
import json
import logging

logger = logging.getLogger(__name__)

# Define Zscaler NSS Web log field order based on standard docs
fields = [
    'time_generated', 'time_received', 'action', 'rule_label', 'url', 'url_category',
    'user', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'http_method',
    'http_status', 'bytes_sent', 'bytes_received', 'user_agent', 'referer',
    'location', 'department', 'reason', 'request_id', 'app_name', 'threat_name',
    'client_country', 'threat_category', 'file_type'
]

# Sample data pools for randomization
users = ['jdoe@example.com', 'asmith@corp.com', 'bjohnson@corp.com', 'mlee@corp.com']
depts = ['Engineering', 'Sales', 'Marketing', 'HR']
actions = ['ALLOW', 'BLOCK', 'ALERT']
categories = ['General-Browsing', 'Social-Media', 'Malware', 'Phishing']
countries = ['US', 'IN', 'CN', 'RU']
threats = ['NONE', 'Malware', 'Phishing', 'Command-Control']

def generate_log_line(i):
    base_time = datetime(2026, 1, 9, 20, 0, 0) + timedelta(seconds=i*2)
    t_gen = base_time
    t_rec = base_time + timedelta(seconds=random.randint(0,5))
    
    row = [
        t_gen.strftime('%Y-%m-%d %H:%M:%S'),
        t_rec.strftime('%Y-%m-%d %H:%M:%S'),
        random.choice(actions),
        f'Rule-Web-{random.choice(["Std", "Block-Malware"])}',
        f'https://www.example{random.randint(1,100)}.com/path{random.randint(1,10)}.html{"?" if i%10==0 else ""}',
        random.choice(categories),
        random.choice(users),
        f'10.0.{random.randint(1,255)}.{random.randint(1,255)}',
        f'{random.randint(93,200)}.{random.randint(100,250)}.{random.randint(1,255)}.{random.randint(1,255)}',
        str(random.randint(50000,65000)),
        '443',
        'HTTPS',
        random.choice(['GET', 'POST']),
        str(random.choice([200, 403, 404])),
        str(random.randint(100,50000)),
        str(random.randint(1000,200000)),
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',
        '-' if random.random() > 0.7 else 'https://intranet.corp.com',
        'San-Jose-CA',
        random.choice(depts),
        'POLICY_ALLOW' if random.choice(actions)=='ALLOW' else 'POLICY_BLOCK',
        f'req-{i:08d}',
        random.choice(['Chrome', 'Office365', 'Zoom']),
        random.choice(threats),
        random.choice(countries),
        random.choice(['PHISHING', 'MALWARE']),
        random.choice(['HTML', 'JS', '-', 'EXE'])
    ]
    return '\t'.join(map(str, row))

# Generate 10000 lines and save to file
log_lines = [generate_log_line(i) for i in range(10000)]
with open("zscaler_nss_web_poc.log", "w") as f:
    f.write('\n'.join(log_lines))

logger.info(f"Generated 10,000 lines to zscaler_nss_web_poc.log")

# Parse and analyze for SOC insights
reader = csv.reader(io.StringIO('\n'.join(log_lines)), delimiter='\t')
parsed = list(reader)

# Top blocked users
blocked_by_user = {}
for row in parsed:
    if len(row) >= 3 and row[2] == 'BLOCK':
        user = row[6]
        blocked_by_user[user] = blocked_by_user.get(user, 0) + 1

top_blocked = sorted(blocked_by_user.items(), key=lambda x: x[1], reverse=True)[:5]
logger.info(f"Top Blocked Users: {top_blocked}")

# Suspicious high bytes malware
suspicious = [row for row in parsed if len(row) >= 20 and 'Malware' in row[5] and int(row[15]) > 100000][:5]
logger.info(f"Suspicious High-Bytes Malware entries: {len(suspicious)}")

# Timeline summary
timeline = {}
for row in parsed:
    if len(row) >= 2:
        hr = row[0][:13]  # YYYY-MM-DD HH
        timeline[hr] = timeline.get(hr, 0) + 1

timeline_summary = sorted(timeline.items(), key=lambda x: int(x[1]), reverse=True)[:10]
logger.info(f"Timeline Summary: {timeline_summary}")

def test_log_synthesizer():
    """Test function for log synthesizer."""
    # Generate a small sample
    sample_lines = [generate_log_line(i) for i in range(100)]
    logger.info(f"Generated {len(sample_lines)} sample lines.")
    # Parse and check
    reader = csv.reader(io.StringIO('\n'.join(sample_lines)), delimiter='\t')
    parsed_sample = list(reader)
    logger.info(f"Parsed {len(parsed_sample)} rows.")
    return parsed_sample

if __name__ == "__main__":
    test_log_synthesizer()
