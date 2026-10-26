# class RoleError(Exception):
#   pass

# def ValidaerRole(role:str):
#   clean_role = role.strip().lower()
#   allowed_roles = ["admin", "analyst", "q"]

#   if clean_role not in allowed_roles:
#     raise RoleError(f'Sorry! But {role} are not allowed')

# try:
#   role = input('Enter Your Role:')
#   ValidaerRole(role)
# except Exception as e:
#   print(e)
# else:
#   print('Access Granted!')

mystring = "Thisisasentenceiliketoreadandwriteagain.loig"
if mystring.rfind('.log'):
  print('File exist')
