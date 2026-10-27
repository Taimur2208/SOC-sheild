from pathlib import Path
import os
class RoleError(Exception):
  pass
class SeverityError(Exception):
  pass

class FileDestinationError(Exception):
  pass

# function for validating user role
def Valider_Role(role:str):
  clean_role = role.strip().lower()
  allowed_roles = ["admin", "analyst", "q"]

  if clean_role not in allowed_roles:
    raise RoleError(f'Sorry! But {role} are not allowed')

# Function for validating file destination
def validate_file_destination(file_path: str):
  clean_path = file_path.strip()
  extension = Path(clean_path).suffix.lower() # .log

  if extension != '.log':
    raise FileDestinationError(f'File must be .log file!!')

  if not os.path.exists(clean_path):
    raise FileDestinationError(f'File {clean_path} does not exist!!')
  
# function for validating Severity
def validate_severity(severe_level:str):
  clean_severe_level = severe_level.strip().upper()

  all_severity_levels = ["ALL", "WARNING", "HIGH", "CRITICAL"]

  if not clean_severe_level in all_severity_levels:
    raise SeverityError("No match found!! You can try ALL/WARNING/CRITICAL/HIGH.")