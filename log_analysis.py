import re
import csv
from collections import defaultdict

# Define file paths and threshold
log_file = "sample.log"
output_csv = "log_analysis_results.csv"
failed_attempt_threshold = 10

# Data structures to store information
ip_request_count = defaultdict(int)
endpoint_access_count = defaultdict(int)
failed_login_attempts = defaultdict(int)

# Log parsing pattern
log_pattern = re.compile(
    r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*\] "(?:GET|POST) (?P<endpoint>\S+) HTTP/1\.1" (?P<status>\d+) .*'
)

# Process the log file
with open(log_file, "r") as file:
    for line in file:
        match = log_pattern.match(line)
        if match:
            ip = match.group("ip")
            endpoint = match.group("endpoint")
            status = match.group("status")

            # Count requests per IP
            ip_request_count[ip] += 1

            # Count accesses to each endpoint
            endpoint_access_count[endpoint] += 1

            # Detect suspicious activity
            if status == "401":
                failed_login_attempts[ip] += 1

# Analyze results
most_accessed_endpoint = max(endpoint_access_count, key=endpoint_access_count.get)
most_accessed_count = endpoint_access_count[most_accessed_endpoint]
suspicious_ips = {
    ip: count for ip, count in failed_login_attempts.items() if count > failed_attempt_threshold
}

# Display results
print("IP Address           Request Count")
for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
    print(f"{ip:20} {count}")

print("\nMost Frequently Accessed Endpoint:")
print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

print("\nSuspicious Activity Detected:")
if suspicious_ips:
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:20} {count}")
else:
    print("No suspicious activity detected.")

# Save results to CSV
with open(output_csv, "w", newline="") as csvfile:
    csvwriter = csv.writer(csvfile)
    
    # Requests per IP
    csvwriter.writerow(["Requests per IP"])
    csvwriter.writerow(["IP Address", "Request Count"])
    for ip, count in sorted(ip_request_count.items(), key=lambda x: x[1], reverse=True):
        csvwriter.writerow([ip, count])
    
    # Most Accessed Endpoint
    csvwriter.writerow([])
    csvwriter.writerow(["Most Accessed Endpoint"])
    csvwriter.writerow(["Endpoint", "Access Count"])
    csvwriter.writerow([most_accessed_endpoint, most_accessed_count])
    
    # Suspicious Activity
    csvwriter.writerow([])
    csvwriter.writerow(["Suspicious Activity"])
    csvwriter.writerow(["IP Address", "Failed Login Count"])
    for ip, count in suspicious_ips.items():
        csvwriter.writerow([ip, count])
