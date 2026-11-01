import json
import pathlib

BaseDIR = pathlib.Path(__file__).resolve().parent.parent

jsonpath = str(BaseDIR / 'config.json')
# configuration data collect krna
def config_app(fileName='jsonPath'):
  with open(fileName, 'r') as opening_file:
    return json.load(opening_file)


