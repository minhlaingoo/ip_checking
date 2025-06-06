import requests
import ipaddress

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

ip_list = expand_ips_from_file(INPUT_FILE)

with open(OUTPUT_FILE, 'w') as out:
    for ip in ip_list:
        try:
            result = check_ip(ip)
            data = result.get('data', {})
            score = data.get('abuseConfidenceScore', 'N/A')
            reports = data.get('totalReports', 'N/A')
            out.write(f"{ip} - Abuse Score: {score} - Reports: {reports}\n")
            print(f"Checked {ip} -> Score: {score}")
        except Exception as e:
            out.write(f"{ip} - Error: {str(e)}\n")
            print(f"Error checking {ip}: {e}")
