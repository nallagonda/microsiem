"""
Zscaler NSS Web Log Data Synthesizer

This module generates synthetic Zscaler NSS web security log data for testing
and demonstration purposes. It creates realistic log entries with various
network traffic patterns, threat types, and user behaviors.

The synthesizer includes:
- Realistic timestamp generation with time progression
- Randomized but plausible network traffic data
- Threat simulation (malware, phishing, etc.)
- User behavior patterns
- SOC-style analysis and insights generation

Generated logs follow the official Zscaler NSS web log format and can be used
for testing anomaly detection algorithms and SIEM functionality.
"""

import csv
import io
import random
from datetime import datetime, timedelta
import json
import logging

# Configure logging for console output
logging.basicConfig(level=logging.INFO, format='%(message)s')
logger = logging.getLogger(__name__)

# Zscaler NSS Web log field specification (based on official documentation)
fields = [
    'time_generated', 'time_received', 'action', 'rule_label', 'url', 'url_category',
    'user', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol', 'http_method',
    'http_status', 'bytes_sent', 'bytes_received', 'user_agent', 'referer',
    'location', 'department', 'reason', 'request_id', 'app_name', 'threat_name',
    'client_country', 'threat_category', 'file_type'
]

# Sample data pools for generating realistic log entries
users = ['jdoe@example.com', 'asmith@corp.com', 'bjohnson@corp.com', 'mlee@corp.com']  # Sample corporate users
depts = ['Engineering', 'Sales', 'Marketing', 'HR']                                   # Department categories
actions = ['ALLOW', 'BLOCK', 'ALERT']                                               # Security actions
categories = ['General-Browsing', 'Social-Media', 'Malware', 'Phishing']            # URL categories
countries = ['US', 'IN', 'CN', 'RU']                                                # Client countries
threats = ['NONE', 'Malware', 'Phishing', 'Command-Control']                       # Threat types

def generate_log_line(i):
    """
    Generate a single synthetic Zscaler NSS web log entry.

    Creates realistic log data with temporal progression and randomized
    network traffic characteristics to simulate real security gateway logs.

    Args:
        i (int): Sequence number used for timestamp progression and request ID

    Returns:
        str: Tab-separated log line matching Zscaler NSS format
    """
    # Generate progressive timestamps starting from a base time
    base_time = datetime(2026, 1, 9, 20, 0, 0) + timedelta(seconds=i*2)
    t_gen = base_time  # Time generated (request arrival)
    t_rec = base_time + timedelta(seconds=random.randint(0,5))  # Time received (processing delay)

    # Build the log entry with realistic but randomized data
    row = [
        t_gen.strftime('%Y-%m-%d %H:%M:%S'),                               # Timestamp generated
        t_rec.strftime('%Y-%m-%d %H:%M:%S'),                               # Timestamp received
        random.choice(actions),                                             # Security action (ALLOW/BLOCK/ALERT)
        f'Rule-Web-{random.choice(["Std", "Block-Malware"])}',            # Rule label
        f'https://www.example{random.randint(1,100)}.com/path{random.randint(1,10)}.html{"?" if i%10==0 else ""}',  # URL
        random.choice(categories),                                         # URL category
        random.choice(users),                                              # User identity
        f'10.0.{random.randint(1,255)}.{random.randint(1,255)}',           # Source IP (internal)
        f'{random.randint(93,200)}.{random.randint(100,250)}.{random.randint(1,255)}.{random.randint(1,255)}',  # Destination IP
        str(random.randint(50000,65000)),                                 # Source port (ephemeral)
        '443',                                                            # Destination port (HTTPS)
        'HTTPS',                                                          # Protocol
        random.choice(['GET', 'POST']),                                   # HTTP method
        str(random.choice([200, 403, 404])),                              # HTTP status code
        str(random.randint(100,50000)),                                   # Bytes sent (client to server)
        str(random.randint(1000,200000)),                                 # Bytes received (server to client)
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64)',                      # User agent
        '-' if random.random() > 0.7 else 'https://intranet.corp.com',     # Referer (70% have referer)
        'San-Jose-CA',                                                    # Location
        random.choice(depts),                                             # Department
        'POLICY_ALLOW' if random.choice(actions)=='ALLOW' else 'POLICY_BLOCK',  # Reason
        f'req-{i:08d}',                                                   # Request ID
        random.choice(['Chrome', 'Office365', 'Zoom']),                   # Application
        random.choice(threats),                                           # Threat name
        random.choice(countries),                                         # Client country
        random.choice(['PHISHING', 'MALWARE']),                          # Threat category
        random.choice(['HTML', 'JS', '-', 'EXE'])                        # File type
    ]
    # Return tab-separated values
    return '\t'.join(map(str, row))

def generate_and_analyze_logs(num_lines=10000):
    """
    Generate synthetic log data and perform SOC-style analysis.

    This function creates a specified number of synthetic Zscaler log entries,
    saves them to a file, and performs basic security analysis including:
    - Top blocked users
    - Suspicious high-bandwidth malware activity
    - Timeline analysis of activity patterns

    Args:
        num_lines (int): Number of log lines to generate (default: 10,000)
    """
    # Generate synthetic log lines
    log_lines = [generate_log_line(i) for i in range(num_lines)]

    # Save generated logs to file for use in analysis
    with open("zscaler_nss_web_poc.log", "w") as f:
        f.write('\n'.join(log_lines))

    logger.info(f"Generated {num_lines} synthetic log lines to zscaler_nss_web_poc.log")

    # Parse the generated logs for SOC-style analysis and insights
    reader = csv.reader(io.StringIO('\n'.join(log_lines)), delimiter='\t')
    parsed = list(reader)

    # Analysis 1: Identify users with most blocked requests (potential policy violations)
    blocked_by_user = {}
    for row in parsed:
        if len(row) >= 3 and row[2] == 'BLOCK':
            user = row[6]  # User field
            blocked_by_user[user] = blocked_by_user.get(user, 0) + 1

    top_blocked = sorted(blocked_by_user.items(), key=lambda x: x[1], reverse=True)[:5]
    logger.info(f"Top Blocked Users (potential security concerns): {top_blocked}")

    # Analysis 2: Find suspicious high-bandwidth malware downloads
    suspicious = [row for row in parsed if len(row) >= 20 and 'Malware' in row[5] and int(row[15]) > 100000][:5]
    logger.info(f"Suspicious High-Bytes Malware entries (potential data exfiltration): {len(suspicious)}")

    # Analysis 3: Create timeline summary of activity by hour
    timeline = {}
    for row in parsed:
        if len(row) >= 2:
            hr = row[0][:13]  # Extract YYYY-MM-DD HH from timestamp
            timeline[hr] = timeline.get(hr, 0) + 1

    timeline_summary = sorted(timeline.items(), key=lambda x: int(x[1]), reverse=True)[:10]
    logger.info(f"Timeline Summary (busiest hours): {timeline_summary}")

def test_log_synthesizer():
    """Test function to verify log generation and parsing functionality."""
    # Generate a small sample of log lines for testing
    sample_lines = [generate_log_line(i) for i in range(100)]
    logger.info(f"Generated {len(sample_lines)} sample log lines for testing.")

    # Parse the sample to verify format correctness
    reader = csv.reader(io.StringIO('\n'.join(sample_lines)), delimiter='\t')
    parsed_sample = list(reader)
    logger.info(f"Successfully parsed {len(parsed_sample)} log entries.")

    # Verify that each parsed row has the expected number of fields
    expected_fields = len(fields)
    valid_rows = sum(1 for row in parsed_sample if len(row) == expected_fields)
    logger.info(f"Format validation: {valid_rows}/{len(parsed_sample)} rows have correct field count.")

    return parsed_sample

if __name__ == "__main__":
    # Generate synthetic logs and run analysis when executed directly
    generate_and_analyze_logs()

    # Also run the test function for validation
    test_log_synthesizer()
