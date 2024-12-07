import re
import csv
from prettytable import PrettyTable
from collections import Counter

# Configuration
log_file_path = "sample.log"  # Path to the log file to be analyzed
output_csv_path = "log_analysis_results.csv"  # Path for the output CSV file
FAILED_LOGIN_THRESHOLD = 5  # Threshold for detecting suspicious activity

def parse_log_file(file_path):
    """
    Parses the log file and extracts relevant information.

    Args:
        file_path (str): The path to the log file.

    Returns:
        list: A list of dictionaries containing parsed log data.
    """
    with open(file_path, "r") as file:
        logs = file.readlines()  # Read all lines from the log file
    log_data = []
    log_pattern = re.compile(
        r'(?P<ip>\d+\.\d+\.\d+\.\d+) - - \[.*?\] "(?P<method>\w+) (?P<endpoint>\S+) HTTP/\d+\.\d+" (?P<status>\d+) .*'
    )
    for line in logs:
        match = log_pattern.match(line)  # Match each line against the regex pattern
        if match:
            log_data.append(match.groupdict())  # Append matched data as a dictionary
    return log_data

def analyze_requests_per_ip(log_data):
    """
    Analyzes the number of requests made by each IP address.

    Args:
        log_data (list): The parsed log data.

    Returns:
        list: A list of tuples containing IP addresses and their request counts, sorted in descending order.
    """
    ip_counter = Counter(log['ip'] for log in log_data)  # Count requests per IP
    return ip_counter.most_common()  # Return sorted list of IPs and counts

def analyze_most_accessed_endpoint(log_data):
    """
    Identifies the most frequently accessed endpoint.

    Args:
        log_data (list): The parsed log data.

    Returns:
        tuple: The most accessed endpoint and its access count, or None if no endpoints are found.
    """
    endpoint_counter = Counter(log['endpoint'] for log in log_data)  # Count accesses per endpoint
    most_accessed = endpoint_counter.most_common(1)  # Get the most accessed endpoint
    return most_accessed[0] if most_accessed else None  # Return the endpoint and count or None

def detect_suspicious_activity(log_data, threshold=FAILED_LOGIN_THRESHOLD):
    """
    Detects suspicious activity based on failed login attempts.

    Args:
        log_data (list): The parsed log data.
        threshold (int): The threshold for failed login attempts to flag as suspicious.

    Returns:
        dict: A dictionary of IP addresses with their failed login counts exceeding the threshold.
    """
    failed_login_counter = Counter(
        log['ip'] for log in log_data if log['status'] == '401' or 'Invalid credentials' in log.get('message', '')
    )
    suspicious_ips = {ip: count for ip, count in failed_login_counter.items() if count > threshold}
    return suspicious_ips  # Return suspicious IPs and their counts

def save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_path):
    """
    Saves the analysis results to a CSV file.

    Args:
        ip_requests (list): The list of IP addresses and their request counts.
        most_accessed_endpoint (tuple): The most accessed endpoint and its count.
        suspicious_activity (dict): The dictionary of suspicious IPs and their failed login counts.
        output_path (str): The path to save the CSV file.
    """
    with open(output_path, mode='w', newline='') as csv_file:
        writer = csv.writer(csv_file)
        
        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_requests:
            writer.writerow([ip, count])
        
        # Write Most Frequently Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Frequently Accessed Endpoint", "Access Count"])
        if most_accessed_endpoint:
            writer.writerow(most_accessed_endpoint)
        
        # Write suspicious activity
        writer.writerow([])
        writer.writerow(["Suspicious Activity Detected"])
        writer.writerow(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def display_results(ip_requests, most_accessed_endpoint, suspicious_activity):
    """
    Displays the analysis results in a formatted table in the terminal.

    Args:
        ip_requests (list): The list of IP addresses and their request counts.
        most_accessed_endpoint (tuple): The most accessed endpoint and its count.
        suspicious_activity (dict): The dictionary of suspicious IPs and their failed login counts.
    """
    print("\n=== Requests Per IP ===")
    table = PrettyTable(["IP Address", "Request Count"])
    for ip, count in ip_requests:
        table.add_row([ip, count])
    print(table)
    
    print("\n=== Most Frequently Accessed Endpoint ===")
    if most_accessed_endpoint:
        print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    else:
        print("No endpoints accessed.")
    
    print("\n=== Suspicious Activity Detected ===")
    if suspicious_activity:
        suspicious_table = PrettyTable(["IP Address", "Failed Login Attempts"])
        for ip, count in suspicious_activity.items():
            suspicious_table.add_row([ip, count])
        print(suspicious_table)
    else:
        print("No suspicious activity detected.")

def main():
    """
    Main function to execute the log analysis workflow.
    """
    # Parse the log file
    log_data = parse_log_file(log_file_path)

    # Analyze the log data
    ip_requests = analyze_requests_per_ip(log_data)
    most_accessed_endpoint = analyze_most_accessed_endpoint(log_data)
    suspicious_activity = detect_suspicious_activity(log_data)

    # Display the results
    display_results(ip_requests, most_accessed_endpoint, suspicious_activity)

    # Save the results to a CSV file
    save_to_csv(ip_requests, most_accessed_endpoint, suspicious_activity, output_csv_path)

if __name__ == "__main__":
    main()