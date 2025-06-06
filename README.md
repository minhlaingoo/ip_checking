import requests
import ipaddress
import time
from tqdm import tqdm
import os

API_KEY = '3ef0881bf4cd648fb05e6fc4b9cfa0d36c80dbf2932a23ef70ab6e8fe1e48e522fdd12a6e2bac053'
INPUT_FILE = 'input.txt'
OUTPUT_FILE = 'abuseip_results.txt'

headers = {
    'Key': API_KEY,
    'Accept': 'application/json'
}

def check_ip(ip):
    url = 'https://api.abuseipdb.com/api/v2/check'
    params = {
        'ipAddress': str(ip),
        'maxAgeInDays': '90'
    }
    response = requests.get(url, headers=headers, params=params)
    return response.json()

def expand_ips_from_file(filename):
    ip_list = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                if '/' in line:
                    network = ipaddress.ip_network(line, strict=False)
                    ip_list.extend(network.hosts())  # skip .0 and .255
                else:
                    ip = ipaddress.ip_address(line)
                    ip_list.append(ip)
            except ValueError:
                print(f"Invalid IP or network: {line}")
    return ip_list

def load_existing_ips(output_file):
    seen = set()
    if os.path.exists(output_file):
        with open(output_file, 'r') as f:
            for line in f:
                if line.strip():
                    seen.add(line.split()[0])
    return seen

ip_list = expand_ips_from_file(INPUT_FILE)
seen_ips = load_existing_ips(OUTPUT_FILE)

with open(OUTPUT_FILE, 'a') as out:
    for ip in tqdm(ip_list, desc="Checking IPs"):
        ip_str = str(ip)
        if ip_str in seen_ips:
            continue
        try:
            result = check_ip(ip)
            data = result.get('data', {})
            score = data.get('abuseConfidenceScore', 'N/A')
            reports = data.get('totalReports', 'N/A')
            out.write(f"{ip_str} - Abuse Score: {score} - Reports: {reports}\n")
            print(f"Checked {ip_str} -> Score: {score}")
        except Exception as e:
            out.write(f"{ip_str} - Error: {str(e)}\n")
            print(f"Error checking {ip_str}: {e}")
        time.sleep(1)


### virus total ###

import requests
import time
import re

VT_API_KEY = 'TYPE API KEY HERE'
INPUT_FILE = 'input.txt'
OUTPUT_FILE = 'output.txt'

headers = {
    'x-apikey': VT_API_KEY
}

def detect_type(value):
    if re.match(r'^[0-9a-fA-F]{32}$', value):      # MD5
        return "files"
    elif re.match(r'^[0-9a-fA-F]{40}$', value):     # SHA1
        return "files"
    elif re.match(r'^[0-9a-fA-F]{64}$', value):     # SHA256
        return "files"
    elif all(c.isdigit() or c == '.' for c in value):  # IP
        return "ip_addresses"
    else:
        return "domains"

def vt_check(value, vt_type):
    url = f"https://www.virustotal.com/api/v3/{vt_type}/{value}"
    response = requests.get(url, headers=headers)
    return response.json()

with open(INPUT_FILE, 'r') as f:
    items = [line.strip() for line in f if line.strip()]

with open(OUTPUT_FILE, 'w') as out:
    for item in items:
        vt_type = detect_type(item)
        try:
            result = vt_check(item, vt_type)

            if 'data' in result and 'attributes' in result['data']:
                stats = result['data']['attributes'].get('last_analysis_stats', {})
                malicious = stats.get('malicious', 0)
                suspicious = stats.get('suspicious', 0)
                harmless = stats.get('harmless', 0)

                out.write(f"{item} ({vt_type}) - Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}\n")
                print(f"Checked {item} -> Malicious: {malicious}")
            elif 'error' in result:
                message = result['error'].get('message', 'Unknown error')
                out.write(f"{item} ({vt_type}) - Error: {message}\n")
                print(f"Error: {item} -> {message}")
            else:
                out.write(f"{item} ({vt_type}) - Error: Unexpected response format\n")
                print(f"Error: {item} -> Unexpected format")

        except Exception as e:
            out.write(f"{item} ({vt_type}) - Exception: {str(e)}\n")
            print(f"Exception checking {item}: {e}")

        time.sleep(15)




