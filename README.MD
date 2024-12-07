# Log File Analysis Project

## Author
Raj Nandan

## Project Description
This project is a Python script designed to analyze log files for extracting and analyzing key information related to IP addresses, endpoints, and suspicious activity. The script processes a specified log file, counts requests per IP address, identifies the most frequently accessed endpoints, and detects potential brute force login attempts.

## Features
- **Count Requests per IP Address**: Parses the log file to extract all IP addresses and calculates the number of requests made by each IP address, displaying the results in descending order.
  
- **Identify the Most Frequently Accessed Endpoint**: Extracts endpoints from the log file and identifies the endpoint accessed the highest number of times.

- **Detect Suspicious Activity**: Flags IP addresses with failed login attempts exceeding a configurable threshold, indicating potential brute force attacks.

- **Output Results**: Displays the results in a clear, organized format in the terminal and saves the results to a CSV file named `log_analysis_results.csv` with the following structure:
  - **Requests per IP**: Columns: `IP Address`, `Request Count`
  - **Most Accessed Endpoint**: Columns: `Endpoint`, `Access Count`
  - **Suspicious Activity**: Columns: `IP Address`, `Failed Login Count`

## Usage
1. Ensure you have Python installed on your machine.
2. Place the log file named `sample.log` in the same directory as the script.
3. Run the script using the command:
   ```bash
   python main.py
   ```
4. The results will be displayed in the terminal and saved to `log_analysis_results.csv`.

## Requirements
- Python 3.x
- `prettytable` library (install using `pip install prettytable`)

## License
This project is licensed under the MIT License.