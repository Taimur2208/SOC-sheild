import json
# configuration data collect krna
def config_app(fileName='/home/taimur/Coding Areana/Python Learning Hub/SOC-sheild/config.json'):
  with open(fileName, 'r') as opening_file:
    return json.load(opening_file)


