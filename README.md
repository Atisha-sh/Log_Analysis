# Log_Analysis_Script 

A Python-based log analysis tool that parses web server logs to extract key insights such as requests per IP address, the most accessed endpoint, and suspicious activity based on failed login attempts. The script processes log files and generates a CSV report with structured data for further analysis.

## Features
### Requests per IP Address
Analyze the log to identify the number of requests made by each IP address.

### Most Accessed Endpoint
Identify the most frequently accessed endpoint, aiding in usage pattern analysis.

### Suspicious Activity Detection
Detect IP addresses with a high count of failed login attempts, flagging potential security threats.

### CSV Report Generation
Outputs a CSV file summarizing requests per IP, the most accessed endpoint, and any suspicious activity.

### Command Line Summary
Displays key findings in the terminal for quick review.

## Technologies Used
### Python: 
The main programming language for parsing and analyzing logs.
### CSV Module: 
For creating structured reports in CSV format.

## File Structure
```
log-analysis/
│
├── log_analysis.py       # Python script to analyze log data
├── sample.log            # Sample web server log file for testing
├── analysis_report.csv   # CSV report generated after log analysis
├── README.md             # Project description (this file)
```

## Real-Life Use Cases
### Web Traffic Monitoring
Understand user behavior and identify peak traffic patterns.

### Security Audits
Detect unusual activities like brute force login attempts.

### System Performance Optimization
Analyze endpoint usage to optimize server resources.


## Future Scope
### Advanced Filtering
Implement filters to analyze logs for specific time frames or user agents.
### Interactive Dashboard
Visualize the insights with a web-based dashboard.
### Real-Time Monitoring
Extend the script to monitor logs in real-time and send alerts.
### Integration with Databases
Store analysis results in a database for historical data comparison.


## Setup Instructions
### 1. Clone the Repository
Download the project to your local machine:
```
git clone https://github.com/your-username/log-analysis.git
cd log-analysis
```
### 2. Install Python
Ensure you have Python 3.x installed on your system. If not, download it here.

### 3. Prepare the Log File
Place your server log file (sample.log) in the project directory. Ensure the log format matches the script's parsing logic.

### 4. Run the Script
Execute the script to analyze the log file:
```
python log_analysis.py
```
### 5. Review the Output
Terminal: Displays key insights.
CSV Report: Review analysis_report.csv for detailed results.


## How It Works
### Log Parsing
The script reads each line of the log file and extracts relevant data such as IP addresses, endpoints, and request statuses.
### Data Aggregation
Counts requests for each IP address.
Tracks access frequency for endpoints.
Identifies failed login attempts.
### Report Generation
The analyzed data is formatted and saved into a CSV file for ease of access and further analysis.


## Contributor
Atisha Shrivas
Email: atisha.shrivas@gmail.com





