# IP Reputation Checker

## Overview

The IP Reputation Checker is a Python script designed to investigate the reputation of IP addresses in bulk using three different services: AbuseIPDB, VirusTotal, and IBM X-Force. It provides valuable insights into an IP address's history, categorization, and risk factors, helping users assess the potential threat associated with a given IP.

## Features

- **AbuseIPDB Investigation:** Retrieve information and reports on IP addresses from AbuseIPDB.
- **VirusTotal Investigation:** Check IP addresses against VirusTotal for malicious indicators.
- **IBM X-Force Investigation:** Perform risk analysis and WHOIS lookup using IBM X-Force.

## Initial Setup

The first time you run the script, you will be prompted to provide API keys for each service. Without these keys, the script won't be able to function. Follow the instructions during the setup process to input the necessary API keys.

## Requirements

Ensure you have the following requirements installed:

- Python 3.x
- Required Python packages (install via `pip install -r requirements.txt`):
  - requests
- At least one API key from AbuseIPDB, VirusTotal or IBM X-Force

## Installation on Linux

1. Open a terminal window.
2. Clone the repository:
   ```bash
   git clone https://github.com/your-username/IP-Reputation-Checker.git
3. Navigate to the project directory:
   ```bash
   cd IP-Reputation-Checker
4. Install the required packages:
    ```bash
   cd IP-Reputation-Checker
## Installation on Windows

1. Download and install Python 3.x from python.org.
2. Download the ZIP file of the repository and extract it to a folder.
3. Open Command Prompt or PowerShell and navigate to the project directory:
    ```bash
    cd path\to\IP-Reputation-Checker
4. Install the required packages:
    ```bash
    pip install -r requirements.txt
## Usage on Linux

1. Navigate to the project directory:
    ```bash
   cd /path/to/IP-Reputation-Checker
2. Open IPs_to_Check.txt with a text editor like nano:
    ```bash
   nano IPs_to_Check.txt
3. Paste the IP addresses you want to check
4. Save and exit IPs_to_Check.txt
5. Run the script with the following command:
    ```bash
    python3 IpReputationChecker.py
6. Follow the on-screen prompts to choose the IP investigation service and provide API keys.
7. The script will process the IP addresses specified in the 'IPs_to_Check.txt' file and display the results.
## Usage on Windows

1. Open the script folder.
2. Open the file IPs_to_Check.txt with a text editor.
3. Paste the IP addresses you want to check.
4. Save and close "IPs_to_Check.txt"
5. Open Command Prompt or PowerShell and navigate to the project directory:
    ```bash
    cd path\to\IP-Reputation-Checker
6. Run the script with the following command:
    ```bash
    python.exe .\IpReputationChecker.py
7. Follow the on-screen prompts to choose the IP investigation service and provide API keys.
8. The script will process the IP addresses specified in the 'IPs_to_Check.txt' file and display the results.
## Options

- **Change AbuseIPDB API Key:**
 If you need to update your AbuseIPDB API key, run the following command in the terminal:

  ```bash
  python IpReputationChecker.py -cak
  or
  python IpReputationChecker.py --changeabusekey

- **Change VirusTotal API Key:**
 If you need to update your VirusTotal API key, run the following command in the terminal:

  ```bash
  python IpReputationChecker.py -cvk
  or
  python IpReputationChecker.py --changeviruskey

- **Change IBM X-Force API Key:**
 If you need to update your IBM X-Force API key, run the following command in the terminal:

  ```bash
  python IpReputationChecker.py -cik
  or
  python IpReputationChecker.py --changeibmkey

## License
This project is licensed under the MIT License. Feel free to use, modify, and distribute it as per the license terms. Contributions are welcome!