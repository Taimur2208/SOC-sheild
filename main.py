import src.utiles as ut
import errors
from src.config import config_app
configuration_dict = config_app()

def print_msg(NameOfApp, VersionOfApp):
  print('_' * 50)
  print(f'{NameOfApp}          version:{VersionOfApp}')
  print('_' * 50)
  print("Enter 'q' for Exit")


def main():
  app_name = configuration_dict.get('app_name')
  app_version = configuration_dict.get('version')

  while True:
    print_msg(NameOfApp=app_name, VersionOfApp=app_version)
    try:
      user_role = input('Your Role:')
      errors.Valider_Role(user_role)
    except Exception as e:
      print(e)
    else:
      if (user_role == 'q'):
        print("Thanks for using SOC-Sheild")
        break
      else:
        print('Access Granted')
        try:
          file_destination = input('Enter the destination of log file you want to inspect:')
          if (file_destination == 'q'):
              print("Thanks for using SOC-Sheild")
              break
        except FileNotFoundError:
          print('The file you want to scan, doesnot exist!!')
    
    
    serverity = input('Severity(ALL/WARNINGS/CRITICALS):')
    if (serverity == 'q'):
          print("Thanks for using SOC-Sheild")
          break

if __name__ == '__main__':
  main()