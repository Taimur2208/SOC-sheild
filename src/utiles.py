import os
from .config import config_app
import csv
import urllib.request

def fetch_honeypot_ips(file_path="/home/taimur/Coding Areana/Python Learning Hub/SOC-sheild/blackIPs.txt"):
  """Fetches malicious IPs from online threat feed. Falls back to a local text file if offline. """
  url = "https://raw.githubusercontent.com/stamparm/ipsum/master/ipsum.txt"
  print("Fetching latest Malicious IPs from Threat Intelligence Feed...")
  try:
    # OPTION 1: Online Threat Feed Fetching
    with urllib.request.urlopen(url, timeout=5) as response:
      data = response.read().decode("utf-8")
      ip_list = [ 
        line.split()[0]
        for line in data.splitlines()
        if line and not line.startswith("#")
        ]
      print( f"Successfully loaded {len(ip_list)} Malicious IPs from Online"   " Feed!" )
      return ip_list
  except Exception as e:
    # OPTION 2: Fallback to Local File (Internet/URL fail hone par)
    print( f"⚠️ Warning: Could not fetch online feed ({e}). Switching to local"     " file..." )
    try:
      with open(file_path, "r") as blacklisted_file:
        ip_list = [
          line.strip().split()[0]
          for line in blacklisted_file
          if line.strip() and not line.strip().startswith("#")
          ]
        print( f"Successfully loaded {len(ip_list)} Malicious IPs from local"    f" file '{file_path}'!" )
        return ip_list
    except FileNotFoundError:
      print( f"Critical Error: Local file '{file_path}' bhi nahi mili!"     " Returning empty list." )
      return []


# list of blacklisted ips is converted into set.
blacklisted_ips_set = set(fetch_honeypot_ips())

# json sy attack_keywords kaa list lyna
attack_keywords = config_app()["attack_keywords"]

# important counters
critical_ips_number = 0
warning_ips = 0


# login attempts
failed_logins = {}


# headers for csv file
headers = [ 
  "Client IP", 
  "Status Code",
  "Timestamp",
  "Requested URL",
  "Severity",
  "Threat Message",
  ]

# function for collecting all data
collected_data = []

# # function for writing data into report file
# def give_result(ip, status_code, timestamp, url, severity, Message):
#   with open('report.csv', 'a', newline='', encoding='utf-8') as reporter:
#     writer = csv.writer(reporter)
#     writer.writerow(headers)



# function for verifying data
def verify_me(ip, status_code, timestamp, url, required_severity):
  global critical_ips_number, warning_ips
  if ip in blacklisted_ips_set:
    critical_ips_number += 1
    severity = "Critical"
    Message = "Honeypot IP detected!"
    if required_severity == 'C':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass

  elif any(pattern in url.lower() for pattern in attack_keywords):
    critical_ips_number += 1
    severity = 'Critical'
    Message = "Malicious IP pattern detected in URL"
    if required_severity == 'C':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass

  elif (status_code == '500'):
    severity = 'High'
    Message = 'Server Error - Possible Exploit Attempt'
    if required_severity == 'H':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
        collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass

  elif (status_code == '401' and int(failed_logins.get(ip)) > config_app()["max_failed_logins"]):
    severity = 'High'
    Message = 'Brute Force Attempt Detected'
    if required_severity == 'H':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass 

  elif (status_code in ['401', '403', '404']):
    warning_ips += 1
    severity = 'Warning'
    Message = f'Suspicious Activity ({status_code})'
    if required_severity == 'W':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass 

  else:
    severity = 'INFO'
    Message = 'Normal Traffic'
    if required_severity == 'I':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    elif required_severity == 'A':
      collected_data.append([ip, status_code, timestamp, url, severity, Message])
    else:
      pass 



def getting_data_from_log(file_destination, required_severity):
  with open(file_destination, 'r') as log_file:
    for line in log_file:
      list_content = line.split(' ')
      list_content.remove('-')
      list_content.remove('-')
      ip = list_content[0]     # ip address from log file
      time_part1 = list_content[1:3]
      time = ','.join(time_part1)    # timestamp from log file
      url_ = list_content[3:6]
      url = ','.join(url_)        # Url from log file
      status_code = list_content[6]       # status codes

      if status_code == '401':
        failed_logins[ip] = failed_logins.get(ip, 0) + 1

      # verifying every ip
      verify_me(ip, status_code, time, url, required_severity)
        
def all_main_action(file_path_toscan = 'dummy.log', required_severity = 'A'):
  getting_data_from_log(file_path_toscan, required_severity)
  with open('report.csv', 'w', newline='', encoding='utf-8') as report:
    writer = csv.writer(report)
    writer.writerow(headers)
    writer.writerows(collected_data)
  print('Report Generated Successfully in excel file: report.csv')


