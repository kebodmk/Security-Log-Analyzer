# Author: Declan Keller
# Date: 4/15/2026
# Purpose: Security log analyzer for failed login attempts

import json, csv

failed_attempts = {}
base = "log_Analyzer/"

# Read .txt file
with open(base + 'logs.txt') as file:
    for line in file:
        parts = line.split('|')

        # Skip malformed lines
        if len(parts) < 3:
            continue

        timestamp = parts[0].strip()
        ip = parts[1].strip()
        status = parts[2].strip()

        if status == 'FAILED':
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1


# Read .json file
with open(base + 'logs.json') as file:
    data = json.load(file)   # loads entire file into Python list

    for entry in data:
        timestamp = entry["timestamp"]
        ip = entry["ip"]
        status = entry["status"]

        if status == 'FAILED':
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1 


# Read .csv file
with open(base + 'logs.csv') as file:
    reader = csv.DictReader(file)

    for row in reader:
        timestamp = row["timestamp"]
        ip = row["ip"]
        status = row["status"]

        if status == 'FAILED':
            failed_attempts[ip] = failed_attempts.get(ip, 0) + 1


print("\nSuspicious IPs:")

# Take all IPs and their failure counts, and sort them from most failed attempts to least
sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

# Print suspicious IPs
for ip, count in sorted_ips:
    if count >= 3:
        print(ip, "is suspicious with", count, "failed attempts")

# Write results to file
with open("Suspicious_ips.txt", "w") as output:
    output.write("Suspicious IPs:\n")

    # Take all IPs and their failure counts, and sort them from most failed attempts to least
    sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips:
        if count >= 3:
            line = f"{ip} is suspicious with {count} failed attempts\n"
            output.write(line)
