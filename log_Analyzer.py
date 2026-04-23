# Author: Declan Keller
# Date: 4/15/2026
# Purpose: Security log analyzer for failed login attempts

import json, csv

failed_attempts = {}

filename = input("Enter filename (logs.txt / logs.json / logs.csv): ")
filepath = filename
try:
# --- TXT FILE ---
    if filename.endswith('.txt'):
        with open(filepath) as file:
            for line in file:
                parts = line.split('|')

                if len(parts) < 3:
                    continue

                timestamp = parts[0].strip()
                ip = parts[1].strip()
                status = parts[2].strip()

                if ip not in failed_attempts:
                    failed_attempts[ip] = []

                failed_attempts[ip].append(timestamp)

    # --- JSON FILE ---
    elif filename.endswith('.json'):
        with open(filepath) as file:
            data = json.load(file)

            for entry in data:
                timestamp = entry["timestamp"]
                ip = entry["ip"]
                status = entry["status"]

                if ip not in failed_attempts:
                    failed_attempts[ip] = []

                failed_attempts[ip].append(timestamp)

    # --- CSV FILE ---
    elif filename.endswith('.csv'):
        with open(filepath) as file:
            reader = csv.DictReader(file)

            for row in reader:
                timestamp = row["timestamp"]
                ip = row["ip"]
                status = row["status"]

                if ip not in failed_attempts:
                    failed_attempts[ip] = []

                failed_attempts[ip].append(timestamp)

    else:
        print("This file is not supported, try another.")
        exit()
except FileNotFoundError:
    print("The file was not found, try another.")
    exit()
except json.JSONDecodeError:
    print("Invalid JSON format.")
    exit()

print("\nSuspicious IPs:")

from datetime import datetime
print("\nRapid Attempt Detection:")

for ip, times in failed_attempts.items():
    # convert to datetime objects
    times = [datetime.strptime(t, "%Y-%m-%d %H:%M:%S") for t in times]
    times.sort()

    for i in range(len(times) - 2):
        if (times[i + 2] - times[i]).seconds <= 30:
            print(f"{ip} shows multiple failed attempts (possible brute-force)\n")
            break

# Sort by most failed attempts
sorted_ips = sorted(failed_attempts.items(), key=lambda x: len(x[1]), reverse=True)

# Print suspicious IPs
for ip, times in sorted_ips:
    count = len(times)
    if count >= 3:
        print(ip, "is suspicious with", count, "failed attempts")

# Write results to file
with open("Suspicious_ips.txt", "w") as output:
    output.write("Suspicious IPs:\n")

    for ip, times in sorted_ips:
        count = len(times)
        if count >= 3:
            output.write(f"{ip} is suspicious with {count} failed attempts\n")
