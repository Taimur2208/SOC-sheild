import src.config as srccon
import src.utiles as ut
import errors
configuration_dict = srccon.config_app()

def print_msg(NameOfApp, VersionOfApp):
  print('_' * 50)
  print(f'{NameOfApp}          version:{VersionOfApp}')
  print('_' * 50)
  print("Enter 'q' for Exit")


def main():
  ut.blacklisted_ips_set
  app_name = configuration_dict.get('app_name')
  app_version = configuration_dict.get('version')


  print_msg(NameOfApp=app_name, VersionOfApp=app_version)
  try:
    user_role = input('Your Role:')
    errors.Valider_Role(user_role)
  except Exception as e:
    print(e)
  else:
    print('Access Granted')
    try:
      file_destination = input('Enter the destination of log file you want to inspect:')
      errors.validate_file_destination(file_destination)
    except Exception as e:
      print(e)
    else:
      try:
        serverity = input('Severity(ALL (A) /WARNINGS (W) /CRITICALS (C) /High (H) /INFO (I):')
        errors.validate_severity(serverity)
      except Exception as e:
        print(e)
      else:
        ut.all_main_action(file_destination, serverity)


if __name__ == '__main__':
  blackListed_ips = ut.blacklisted_ips_set
  main()