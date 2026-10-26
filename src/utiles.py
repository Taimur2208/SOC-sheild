import os
import csv
import urllib.request
from config import config_app
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
  "Timestamp",
  "Requested URL",
  "Status Code",
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
def verify_me(ip, status_code, timestamp, url):
  global critical_ips_number, warning_ips
  if ip in blacklisted_ips_set:
    critical_ips_number += 1
    severity = "Critical"
    Message = "Honeypot IP detected!"
    collected_data.append([ip, status_code, timestamp, url, severity, Message])

  elif any(pattern in url.lower() for pattern in attack_keywords):
    critical_ips_number += 1
    severity = 'Critical'
    Message = "Malicious IP pattern detected in URL"
    collected_data.append([ip, status_code, timestamp, url, severity, Message])

  elif (status_code == '500'):
    severity = 'High'
    Message = 'Server Error - Possible Exploit Attempt'
    collected_data.append([ip, status_code, timestamp, url, severity, Message])

  elif (status_code == '401' and int(failed_logins.get(ip)) > config_app()["max_failed_logins"]):
    severity = 'High'
    Message = 'Brute Force Attempt Detected'
    collected_data.append([ip, status_code, timestamp, url, severity, Message])

  elif (status_code in ['401', '403', '404']):
    warning_ips += 1
    severity = 'Warning'
    Message = f'Suspicious Activity ({status_code})'
    collected_data.append([ip, status_code, timestamp, url, severity, Message])

  else:
    severity = 'INFO'
    Message = 'Normal Traffic'
    collected_data.append([ip, status_code, timestamp, url, severity, Message])



def getting_data_from_log(file_destination):
  with open(file_destination) as log_file:
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
      verify_me(ip, status_code, time, url)
        

getting_data_from_log('dummy.log')
with open('report.csv', 'w', newline='', encoding='utf-8') as report:
  writer = csv.writer(report)
  writer.writerow(headers)
  writer.writerows(collected_data)