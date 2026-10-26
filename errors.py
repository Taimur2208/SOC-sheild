class RoleError(Exception):
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

  if clean_path.rfind
