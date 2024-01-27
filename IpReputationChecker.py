import json
import re
import requests
import os
import logging
import concurrent.futures
import argparse
import sys
# Create a 'logs' directory if it doesn't exist
if not os.path.exists('logs'):
    os.makedirs('logs')

# Set up the logging configuration
log_file = os.path.join('logs', 'IpReputationChecker.log')
logging.basicConfig(filename=log_file, level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_config_file():
    try:
        script_directory = os.path.dirname(os.path.abspath(__file__))
        file_path = os.path.join(script_directory, 'Config_files', 'config.json')
        with open(file_path, 'r') as file:
            data = json.load(file)
    except FileNotFoundError:
        print(f"File not found - Creating a new config file at: {file_path}")
        data = {}
        save_config_file(file_path, data)
    except json.JSONDecodeError:
        print(f"Error: Invalid JSON format in file - {file_path}")
        data = {}
    except Exception as e:
        print(f"An error occurred: {e}")
        data = {}
    
    return data
def load_variables():
    script_directory = os.path.dirname(os.path.abspath(__file__))
    config_file = load_config_file()
    config_file_path = os.path.join(script_directory, 'Config_files', 'config.json')
    return script_directory, config_file, config_file_path

def save_config_file(file_path, data):
    with open(file_path, 'w') as file:
        json.dump(data, file, indent=2)

def load_api_keys():
    variables = load_variables()
    config_file = variables[1]
    config_file_path = variables[2]
    abuse_ipdb_key = config_file.get('abuseipdb_key')
    virus_total_key = config_file.get('VirusTotal_key')
    ibm_xforce_key = config_file.get('Ibm_X-force_key')

    while not abuse_ipdb_key:
        user_have_abuse_ipdb_key = input("Do you have an AbuseIPDB API key? (yes/no): ").lower()
        if user_have_abuse_ipdb_key == "yes":
            abuse_ipdb_key = input("Enter AbuseIPDB API key: ")
            config_file['abuseipdb_key'] = abuse_ipdb_key
        elif user_have_abuse_ipdb_key == "no":
            abuse_ipdb_key = " "
            config_file['abuseipdb_key'] = abuse_ipdb_key
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    while not virus_total_key:
        user_have_virus_total_key = input("Do you have an VirusTotal API key (yes/no): ").lower()
        if user_have_virus_total_key == "yes":
            virus_total_key = input("Enter VirusTotal API key: ")
            config_file['VirusTotal_key'] = virus_total_key
        elif user_have_virus_total_key == "no":
            virus_total_key = " "
            config_file['VirusTotal_key'] = virus_total_key
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    while not ibm_xforce_key:
        user_have_ibm_xforce_key = input("Do you have an IBM X-Force API key (yes/no): ").lower()
        if user_have_ibm_xforce_key == "yes":
            ibm_xforce_key = input("Enter IBM X-Force API key: ")
            config_file['Ibm_X-force_key'] = ibm_xforce_key
        elif user_have_ibm_xforce_key == "no":
            ibm_xforce_key = " "
            config_file['Ibm_X-force_key'] = ibm_xforce_key
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

    save_config_file(config_file_path, config_file)

    return abuse_ipdb_key, virus_total_key, ibm_xforce_key

def modify_abuse_ipdb_key():
    variables = load_variables()
    config_file = variables[1]
    config_file_path = variables[2]
    abuse_ipdb_key = config_file.get('abuseipdb_key')
    
    while True:
        print(f"Current AbuseIPDB API key: {abuse_ipdb_key}")
        change_key = input("\nDo you want to change the AbuseIPDB API key? (yes/no): ").lower()

        if change_key == 'yes':
            new_key = input("\nEnter new AbuseIPDB API key: ")
            config_file['abuseipdb_key'] = new_key
            save_config_file(config_file_path, config_file)
            print("\nNew AbuseIPDB API key saved")
            break
        elif change_key == "no":
            print("No changes to the AbuseIPDB API key")
            break
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

def modify_virus_total_key():
    variables = load_variables()
    config_file = variables[1]
    config_file_path = variables[2]
    virus_total_key = config_file.get('VirusTotal_key')
    
    while True:
        print(f"Current VirusTotal API key: {virus_total_key}")
        change_key = input("\nDo you want to change the VirusTotal API key? (yes/no): ").lower()
        if change_key == 'yes':
            new_key = input("\nEnter new VirusTotal API key: ")
            config_file['VirusTotal_key'] = new_key
            save_config_file(config_file_path, config_file)
            print("\nVirusTotal API key saved")
        elif change_key == "no":
            print("No changes to the VirusTotal API key")
            exit
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")
        
        return config_file['VirusTotal_key']

def modify_ibm_xforce_key():
    variables = load_variables()
    config_file = variables[1]
    config_file_path = variables[2]
    ibm_xforce_key = config_file.get('Ibm_X-force_key')

    while True:
        print(f"Current IBM X-Force API key: {ibm_xforce_key}")
        change_key = input("\nDo you want to change the IBM X-Force API key? (yes/no): ").lower()
        if change_key == 'yes':
            new_key = input("\nEnter new IBM X-Force API key: ")
            config_file['Ibm_X-force_key'] = new_key
            save_config_file(config_file_path, config_file)
            print("\nIBM X-Force API key saved")
        elif change_key == "no":
            print("No changes to the IBM X-Force API key")
            exit
        else:
            print("Invalid input. Please enter 'yes' or 'no'.")

        return config_file['Ibm_X-force_key']

def extract_ips_from_file(file_name):
    with open(file_name, 'r', encoding='utf-8') as file:  # Specify the encoding
        data = file.read()
        ip_pattern = re.findall(r'(?:\d{1,3}\.){3}\d{1,3}|(?:[A-Fa-f0-9]{1,4}:+)+[A-Fa-f0-9]{0,4}', data)
    return ip_pattern

def load_categories_and_country_codes():
    variables = load_variables()
    script_directory = variables[0]
    categories_file_path = os.path.join(script_directory, 'Config_files', 'categories.json')
    country_codes_file_path = os.path.join(script_directory, 'Config_files', 'country_codes.json')
    # Read JSON data from the categories file
    with open(categories_file_path, 'r') as file:
        categories_data = file.read()

    # Load JSON data into a dictionary with keys as integers
    categories_data = {int(k): v for k, v in json.loads(categories_data).items()}

    # Read JSON data from the country_codes file
    with open(country_codes_file_path, 'r') as file:
        country_codes_data = file.read()

    country_codes_dict = json.loads(country_codes_data)

    return categories_data, country_codes_dict

def check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip):
    url = f'https://api.abuseipdb.com/api/v2/check'
    headers = {
        'Key': abuse_ipdb_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': '30',
    }
    logging.info(f"Requesting check for IP: {ip}")
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get("data")
        countrycode = data.get("countryCode")
        isp = data.get("isp")
        total_reports = data.get("totalReports")
        country = country_codes_dict.get(countrycode)
        log_info = f"Check for IP {ip}: Country - {country}, ISP - {isp}, Total Reports - {total_reports}"
        logging.info(log_info)
    else:
        logging.error(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")  
    return country, isp, total_reports

def check_reports_on_abuse_ipdb(abuse_ipdb_key, categories_data, ip):
    url = f'https://api.abuseipdb.com/api/v2/reports'
    headers = {
        'Key': abuse_ipdb_key,
        'Accept': 'application/json',
        'Content-Type': 'application/json'
    }

    params = {
        'ipAddress': ip,
        'maxAgeInDays': '30',
        'perPage':'1'
    }
    logging.info(f"Requesting reports for IP: {ip}")
    response = requests.get(url, headers=headers, params=params)

    if response.status_code == 200:
        data = response.json().get("data")
        category = data.get('results', [{}])[0].get('categories', [])[0]
        reportedAt = data.get('results', [{}])[0].get('reportedAt')
        if category in categories_data:
            translated_category = categories_data[category]
            log_info = f"Reports found for IP {ip}: Category - {translated_category}, Reported At - {reportedAt}"
            logging.info(log_info)
        else:
            logging.warning(f"Report Category not found for IP {ip}")
    else:
        logging.error(f"Failed to fetch reports for IP {ip}. Status code: {response.status_code}")  
    return translated_category, reportedAt

def abuse_ipdb_logic():
    variables = load_variables()
    config_file = variables[1]
    abuse_ipdb_key = config_file.get('abuseipdb_key')
    categories_data, country_codes_dict = load_categories_and_country_codes()

    ips_to_check = extract_ips_from_file("IPs_to_Check.txt")

    ip_info = ""
    for ip in ips_to_check:
        country, isp, total_reports = check_ip_on_abuse_ipdb(abuse_ipdb_key, country_codes_dict, ip)
        output_line = f"{ip} {country} {isp} "
        
        if total_reports >= 1:
            translated_category, reportedAt = check_reports_on_abuse_ipdb(abuse_ipdb_key, categories_data, ip)
            output_line += f"Reported for {translated_category} at {reportedAt}\n"
        else:
            output_line += "No reports\n"
        
        ip_info += output_line

    return ip_info

def check_ip_on_virustotal(ip):
    variables = load_variables()
    config_file = variables[1]
    virus_key = config_file.get('VirusTotal_key')
    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip}'
    headers = {
    "accept": "application/json",
    "x-apikey": f"{virus_key}"
    }
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        data = response.json().get("data")
        isp = data.get("attributes").get("as_owner")
        countrycode = data.get("attributes").get("country")
        malicious_count = data.get("attributes").get("last_analysis_stats").get("malicious")
    else:
        print(f"Failed to fetch data for IP {ip}. Status code: {response.status_code}")  
    return countrycode, isp, malicious_count

def virustotal_logic():
    ips_to_check = extract_ips_from_file("IPs_to_Check.txt")
    ip_info = ""
    
    for ip in ips_to_check:
        country, isp, malicious_count = check_ip_on_virustotal(ip)
        output_line = f"{ip} {country} {isp} "
        
        if malicious_count >= 1:
            output_line += f"On VirusTotal {malicious_count} security vendors flagged this IP address as malicious\n"
        else:
            output_line += "No reports on VirusTotal\n"
        
        ip_info += output_line
    return ip_info


def main_command():
    variables = load_variables()
    config_file = variables[1]
    abuse_ipdb_key = config_file.get('abuseipdb_key')
    virus_key = config_file.get('VirusTotal_key')
    ibm_key = config_file.get('Ibm_X-force_key')

    print("Welcome to the IP Reputation Checker Script!")
    print("This script allows you to investigate the reputation of IP addresses in bulk on AbuseIPDB, VirusTotal, or IBM X-Force.\n")
    
    while True:
        user_choice = input("Which service you want to use to investigate the IP addresses (AbuseIPDB/VirusTotal/IBMX-Force): ").lower()
        if user_choice == "abuseipdb":
            if abuse_ipdb_key == " ":
                print("There isn't an API key for AbuseIPDB")
                print("To add a new API key, run: python3 IpReputationChecker.py -cak")
                break
            else:
                print("AbuseIPDB IP addresses investigation:\n")
                print(abuse_ipdb_logic())
                break
        elif user_choice == "virustotal":
            if virus_key == " ":
                print("There isn't an API key for VirusTotal")
                print("To add a new API key, run: python3 IpReputationChecker.py -cvk")
                break
            else:
                print("VirusTotal IP addresses investigation:\n")
                print(virustotal_logic())
                break
        elif user_choice == "ibmx-force":
            if ibm_key == " ":
                print("There isn't an API key for IBM X-Force")
                print("To add a new API key, run: python3 IpReputationChecker.py -cik")
                break
            else:
                print("ibmx-force script")
                break
        elif user_choice == "exit":
            break
        else:
            print("No valid options provided. Use AbuseIPDB, VirusTotal or IBMX-Force")

def main():
    # Handle command line arguments
    parser = argparse.ArgumentParser(
        description='Investigate IP addresses on reputation sites',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('-cak', '--changeabusekey', action='store_true', help='Modify the AbuseIPDB API key')
    parser.add_argument('-cvk', '--changeviruskey', action='store_true', help='Modify the VirusTotal API key')
    parser.add_argument('-cik', '--changeibmkey', action='store_true', help='Modify the IBM X-Force API key')

    args = parser.parse_args()

    if args.changeabusekey:
        # Add logic to modify AbuseIPDB API key
        modify_abuse_ipdb_key()
    elif args.changeviruskey:
        # Add logic to modify VirusTotal API key
        print("Changing VirusTotal API key...")
    elif args.changeibmkey:
        # Add logic to modify IBM X-Force API key
        print("Changing IBM X-Force API key...")
    elif len(sys.argv) == 1:
        # Handle the case of running the script without options
        main_command()
    else:
        # Handle the case of unrecognized options
        print("No valid options provided. Use -h or --help for help.")
    return


if __name__ == "__main__":
    main()
