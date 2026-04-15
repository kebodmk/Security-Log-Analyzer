# Author: Declan Keller
# Date: 4/15/2026
# Purpose: Security log analyzer for failed login attempts

failed_attempts = {}

# Read file safely
with open('log_Analyzer/logs.txt') as file:
    for line in file:
        parts = line.split('|')

        # Skip malformed lines
        if len(parts) < 3:
            continue

        timestamp = parts[0].strip()
        ip = parts[1].strip()
        status = parts[2].strip()

        if status == 'FAILED':
            if ip not in failed_attempts:
                failed_attempts[ip] = 0
            
            failed_attempts[ip] += 1

print("\nSuspicious IPs:")

# Take all IPs and their failure counts, and sort them from most failed attempts to least
sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

# Print suspicious IPs
for ip, count in sorted_ips:
    if count >= 3:
        print(ip, "is suspicious with", count, "failed attempts")

# Write results to file
with open("log_Analyzer/Suspicious_ips.txt", "w") as output:
    output.write("Suspicious IPs:\n")

    # Take all IPs and their failure counts, and sort them from most failed attempts to least
    sorted_ips = sorted(failed_attempts.items(), key=lambda x: x[1], reverse=True)

    for ip, count in sorted_ips:
        if count >= 3:
            line = f"{ip} is suspicious with {count} failed attempts\n"
            output.write(line)
