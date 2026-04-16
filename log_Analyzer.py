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

                if status == 'FAILED':
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # --- JSON FILE ---
    elif filename.endswith('.json'):
        with open(filepath) as file:
            data = json.load(file)

            for entry in data:
                timestamp = entry["timestamp"]
                ip = entry["ip"]
                status = entry["status"]

                if status == 'FAILED':
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

    # --- CSV FILE ---
    elif filename.endswith('.csv'):
        with open(filepath) as file:
            reader = csv.DictReader(file)

            for row in reader:
                timestamp = row["timestamp"]
                ip = row["ip"]
                status = row["status"]

                if status == 'FAILED':
                    failed_attempts[ip] = failed_attempts.get(ip, 0) + 1

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

# Sort by most failed attempts
sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

# Print suspicious IPs
for ip, count in sorted_ips:
    if count >= 3:
        print(ip, "is suspicious with", count, "failed attempts")

# Write results to file
with open("Suspicious_ips.txt", "w") as output:
    output.write("Suspicious IPs:\n")

    for ip, count in sorted_ips:
        if count >= 3:
            output.write(f"{ip} is suspicious with {count} failed attempts\n")
