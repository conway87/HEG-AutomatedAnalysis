import os
import pandas as pd
from openpyxl import Workbook, load_workbook


# Get all .csv files in the current directory
csv_files = [f for f in os.listdir('.') if f.endswith('.csv')]

# Loop through each .csv file and convert to .xlsx
for csv_file in csv_files:
    # Get the file name without the extension
    file_name = os.path.splitext(csv_file)[0]
    # Read the .csv file into a pandas dataframe
    df = pd.read_csv(csv_file)
    # Write the dataframe to an .xlsx file with the same name
    df.to_excel(f'{file_name}.xlsx', index=None)
    os.remove(csv_file)






def update_highlight_and_notes(df):
    # Define conditions and notes
    conditions_and_notes = [

        # RunDLL
        ((df['Id'] == 4688) & (df['Message'].str.contains('rundll32.exe  devmgr.dll DeviceManager_Execute')), 'IOC', 'RunDLL'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'C:\\Windows\\system32\\devmgmt.msc /s')), 'IOC', 'RunDLL'),

        # WMIC
        ((df['Id'] == 4688) & (df['Message'].str.contains('wmic  os get Caption,BuildNumber,Version,ServicePackMajorVersion')), 'IOC', 'WMIC'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('wmic  qfe list full')), 'IOC', 'WMIC'),

        # Encoded PowerShell
        ((df['Id'] == 4688) & (df['Message'].str.contains('powershell  -exec bypass -e')), 'IOC', 'Encoded PowerShell Commands'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'C:\\Windows\\System32\\calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'C:\\Windows\\System32\\win32calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),

        # Firewall - Create Exclusions
        ((df['Id'] == 4688) & (df['Message'].str.contains('advfirewall firewall add rule name="HEG_Firewall-Exclusion-CMD" dir=in action=allow enable=yes')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Creation started'),
                
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('Active=TRUE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Added in Registry'),       
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('Active=TRUE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Added in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('Active=TRUE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Added in Registry'),       
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('Active=TRUE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Added in Registry'),      
        ((df['Id'] == 4946) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Created'),
        ((df['Id'] == 4946) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Created'),
        ((df['Id'] == 4946) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Created'),
        ((df['Id'] == 4946) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Created'),



        # Firewall - Modify Exclusions

        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('App=')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Modified in Registry'),
        ((df['Id'] == 4947) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Modified'),
        ((df['Id'] == 4947) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Modified'),
        ((df['Id'] == 4947) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Modified'),
        ((df['Id'] == 4947) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Modified'),



        # Firewall - Disable Exclusions
        ((df['Id'] == 4688) & (df['Message'].str.contains('advfirewall firewall set rule name="HEG_Firewall-Exclusion-CMD" new enable=no')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Disabling started'),
        
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('Active=FALSE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Disabled in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('Active=FALSE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Disabled in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('Active=FALSE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Disabled in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('Active=FALSE')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Disabled in Registry'),
        
        

        # Firewall - Delete Exclusions
        ((df['Id'] == 4688) & (df['Message'].str.contains('advfirewall firewall delete rule name="HEG_Firewall-Exclusion-CMD"')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Deletion Started'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Registry value deleted')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Removed from Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Registry value deleted')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Removed from Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Registry value deleted')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Removed from Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Registry value deleted')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Removed from Registry'),
        ((df['Id'] == 4948) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Deleted'),
        ((df['Id'] == 4948) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')), 'IOC', 'HEG_Firewall-Exclusion-JS || Deleted'),
        ((df['Id'] == 4948) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Deleted'),
        ((df['Id'] == 4948) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Deleted'),

        # Firewall - Firewall Disabled
        ((df['Id'] == 4688) & (df['Message'].str.contains('advfirewall set allprofiles state off')), 'IOC', 'Process Chain Started: Disable Windows Firewall'),
        ((df['Id'] == 4950) & (df['Message'].str.contains('Value:	No')), 'IOC', 'Firewall Disabled'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('advfirewall set allprofiles state on')), 'CleanUp', 'Process Chain Started: Re-Enable Windows Firewall'),
        ((df['Id'] == 4950) & (df['Message'].str.contains('Value:	Yes')), 'CleanUp', 'Firewall Re-Enabled'),
        
        # Firewall - Misc
        ((df['Id'] == 5447) & (df['Message'].str.contains('HEG_Firewall-Exclusion-')), 'IOC', ''),



        # Scheduled Task - Misc
        ((df['Id'] == 4657) & (df['Message'].str.contains('HEG_Scheduled-Task-')), 'IOC', ''),


        # Scheduled Task - Create
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'/CREATE /SC DAILY /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Creation Started'),
        ((df['Id'] == 4698) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Created'),
        ((df['Id'] == 4698) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Created'),
        ((df['Id'] == 4698) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Created'),
        ((df['Id'] == 4698) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Created'),


        # Scheduled Task - Modify
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'/CHANGE /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Modification Started'),   
        ((df['Id'] == 4702) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Modified'),
        ((df['Id'] == 4702) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Modified'),
        ((df['Id'] == 4702) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Modified'),
        ((df['Id'] == 4702) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Modified'),


        # Scheduled Task - Disable
        ((df['Id'] == 4701) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Disabled'),
        ((df['Id'] == 4701) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Disabled'),
        ((df['Id'] == 4701) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Disabled'),
        ((df['Id'] == 4701) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Disabled'),


        # Scheduled Task - Delete
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'/DELETE /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Deletion Started'),
        ((df['Id'] == 4699) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Deleted'),
        ((df['Id'] == 4699) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Deleted'),
        ((df['Id'] == 4699) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Deleted'),
        ((df['Id'] == 4699) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Deleted'),


        # Service Operations - Create
        ((df['Id'] == 4688) & (df['Message'].str.contains('create HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Creation Started'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Service-CMD')) & (~df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-CMD || Added in Registry'),       
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Service-PS')) & (~df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-PS || Added in Registry'),
        ((df['Id'] == 4697) & (df['Message'].str.contains('HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Created'),
        ((df['Id'] == 4697) & (df['Message'].str.contains('HEG_Service-PS')), 'IOC', 'HEG_Service-PS || Created'),


        # Service Operations - Modify
        ((df['Id'] == 4688) & (df['Message'].str.contains('config HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Modification Started'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Modified in Registry'),
        
        # Service Operations - Disable
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('HEG_Service-PS')), 'IOC', 'HEG_Service-PS || Disabled in Registry'),


        # Service Operations - Delete
        ((df['Id'] == 4688) & (df['Message'].str.contains('delete HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Deletion Started'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Service-CMD')) & (df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-CMD || Deleted in Registry'),       
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Service-PS')) & (df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-PS || Deleted in Registry'),       







        # User Operations
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User-CMD')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-CMD || Creation Started'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User-PS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-PS || Creation Started'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User-JS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-JS || Creation Started'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User-VBS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-VBS || Creation Started'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User-WMIC')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-WMIC || Creation Started'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('HEG_User ')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User || Creation Started'),       
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User-CMD')), 'IOC', 'HEG_User-CMD || Created'),
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User-PS')), 'IOC', 'HEG_User-PS || Created'),
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User-JS')), 'IOC', 'HEG_User-JS || Created'),
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User-VBS')), 'IOC', 'HEG_User-VBS || Created'),
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User-WMIC')), 'IOC', 'HEG_User-WMIC || Created'),
        ((df['Id'] == 4720) & (df['Message'].str.contains('HEG_User ')), 'IOC', 'HEG_User || Created'),        
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User-CMD')), 'IOC', 'HEG_User-CMD || Enabled'),
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User-PS')), 'IOC', 'HEG_User-PS || Enabled'),
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User-JS')), 'IOC', 'HEG_User-JS || Enabled'),
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User-VBS')), 'IOC', 'HEG_User-VBS || Enabled'),
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User-WMIC')), 'IOC', 'HEG_User-WMIC || Enabled'),
        ((df['Id'] == 4722) & (df['Message'].str.contains('HEG_User ')), 'IOC', 'HEG_User || Enabled'),        
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User-CMD')), 'IOC', 'HEG_User-CMD || Changed'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User-PS')), 'IOC', 'HEG_User-PS || Changed'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User-JS')), 'IOC', 'HEG_User-JS || Changed'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User-VBS')), 'IOC', 'HEG_User-VBS || Changed'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User-WMIC')), 'IOC', 'HEG_User-WMIC || Changed'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('HEG_User ')), 'IOC', 'HEG_User || Changed'),        
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User-CMD')), 'IOC', 'HEG_User-CMD || Password Reset'),
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User-PS')), 'IOC', 'HEG_User-PS || Password Reset'),
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User-JS')), 'IOC', 'HEG_User-JS || Password Reset'),
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User-VBS')), 'IOC', 'HEG_User-VBS || Password Reset'),
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User-WMIC')), 'IOC', 'HEG_User-WMIC || Password Reset'),
        ((df['Id'] == 4724) & (df['Message'].str.contains('HEG_User ')), 'IOC', 'HEG_User || Password Reset'),
    
        ((df['Id'] == 4738) & (df['Message'].str.contains('t Expire Password')) & (df['Message'].str.contains('HEG_User')), 'IOC', 'HEG_User || Updated to Non-Expiring Password'),
        ((df['Id'] == 4738) & (df['Message'].str.contains('Account Disabled')) & (df['Message'].str.contains('HEG_User')), 'IOC', 'HEG_User || Updated to Account Disabled'),
        ((df['Id'] == 4725) & (df['Message'].str.contains('HEG_User')), 'IOC', 'HEG_User || Account Disabled'),




        ((df['Id'] == 4732), 'IOC', 'Added to Local Security Group'),
        ((df['Id'] == 4728), 'IOC', 'Added to Global Group'),
        ((df['Id'] == 4733), 'IOC', 'Removed from Local Security Group'),
        ((df['Id'] == 4729), 'IOC', 'Removed from Global Security Group'),
        ((df['Id'] == 4726), 'IOC', 'User Account Deleted'),





        # Registy - Create
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'REG  ADD HKEY_CURRENT_USER\\Console\\HEG_Registry-Key-CMD\\')), 'IOC', 'HEG_Registry-Key-CMD || Creation Started'),     
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Registry-Key-CMD')), 'IOC', 'HEG_Registry-Key-CMD || Added in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Registry-Key-PS')), 'IOC', 'HEG_Registry-Key-PS || Added in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Registry-Key-JS')), 'IOC', 'HEG_Registry-Key-JS || Added in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('New registry value created')) & (df['Message'].str.contains('HEG_Registry-Key-VBS')), 'IOC', 'HEG_Registry-Key-VBS || Added in Registry'),       


        # Registy - Modify
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('HEG_Registry-Key-VBS')), 'IOC', 'HEG_Registry-Key-VBS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('HEG_Registry-Key-PS')), 'IOC', 'HEG_Registry-Key-PS || Modified in Registry'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('Existing registry value modified')) & (df['Message'].str.contains('HEG_Registry-Key-JS')), 'IOC', 'HEG_Registry-Key-JS  || Modified in Registry'),



        # Registy - Delete
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'REG  DELETE HKEY_CURRENT_USER\\Console\\HEG_Registry-Key-CMD\\')), 'IOC', 'HEG_Registry-Key-CMD || Deletion Started'),
       

        # Registy - MISC
        ((df['Id'] == 4688) & (df['Message'].str.contains('reg  import RegistryFile.reg')), 'IOC', 'Modify Registry Key'),






        # BruteForce
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Tools\\psexec  -u Administrator -p password')), 'IOC', 'PSExec Attempting Random Password'),
        ((df['Id'] == 4776) & (df['Message'].str.contains('Guest')), 'IOC', 'Guest Login Failed'),
        ((df['Id'] == 4776) & (df['Message'].str.contains('Administrator')) & (~df['Message'].str.contains('Guest')), 'IOC', 'Admin Login Failed'),
        ((df['Id'] == 4625) & (df['Message'].str.contains('Guest')), 'IOC', 'Guest Login Failed'),
        ((df['Id'] == 4625) & (df['Message'].str.contains('Administrator')) & (~df['Message'].str.contains('Guest')), 'IOC', 'Admin Login Failed'),
        ((df['Id'] == 4616), 'IOC', 'System time changed'),
        ((df['Id'] == 4740), 'IOC', 'Account Lockout'),
        ((df['Id'] == 4611), 'IOC', 'Trusted Logon Process Registered'),

        # Searching for .key files
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'dir c:\\Users\\Public /b /s .key')), 'IOC', 'Process Chain Started: Search for .key files'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'findstr  /e .key')), 'IOC', 'Findstr launched'),
        
        # WinRM
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'quickconfig -q')), 'IOC', 'WinRM'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'sc  stop winrm')), 'CleanUp', 'WinRM Removal'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'config winrm start= disabled')), 'CleanUp', 'WinRM Removal'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'C:\\Windows\\PSEXESVC.exe')), 'IOC', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'WinRM')), 'IOC', ''),
        ((df['Id'] == 5140), 'IOC', ''),
        ((df['Id'] == 5145), 'IOC', ''),

        # PSExec
        ((df['Id'] == 4688) & (df['Message'].str.contains('ping google.ie')), 'IOC', 'PSExec'),
        ((df['Id'] == 4688) & (df['Message'].str.contains('ping  google.ie')), 'IOC', 'PSExec'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('PSEXE')), 'IOC', 'PSExec'),
        ((df['Id'] == 4697) & (df['Message'].str.contains('PSEXE')), 'IOC', 'PSExec'),
        

        # Log Resize
        ((df['Id'] == 4657) & (df['Message'].str.contains('EventLog-Application')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('EventLog-System')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 4657) & (df['Message'].str.contains('EventLog-System')), 'IOC', 'Event Log Resize'),

        # Log Disable
        ((df['Id'] == 4657) & (df['Message'].str.contains(r'Microsoft-Windows-Bits-Client/Operational')), 'IOC', 'Event Log Enable/Disable'),
        ((df['Id'] == 4657) & (df['Message'].str.contains(r'Microsoft-Windows-HelloForBusiness/Operational')), 'IOC', 'Event Log Enable/Disable'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'/e:false')), 'IOC', 'Disable Logging'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'/e:true')), 'CleanUp', 'Re-Enable Logging'),

        # Log Delete
        ((df['Id'] == 4688) & (df['Message'].str.contains('wevtutil.exe" cl ')), 'IOC', 'Log Cleared'),    
        
        # Script Operations
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Execution\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Defense_Evasion\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Persistence\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Privilege_Escalation\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Credential_Access\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Exfiltration\\')), 'Script Operations', ''),        
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'\\Scripts\\Lateral_Movement\\')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'create shadow /for=C:')), 'Script Operations', ''),
        ((df['Id'] == 4688) & (df['Message'].str.contains('delete shadows')), 'IOC', 'Deleting Shadow Copies'),
        ((df['Id'] == 4688) & (df['Message'].str.contains(r'cleanup.bat:')), 'Script Operations', ''),


        # Rogue Root Cert
        ((df['Id'] == 5058), 'IOC', 'Root Certificate'),
        ((df['Id'] == 5061), 'IOC', 'Root Certificate'),
        ((df['Id'] == 5059), 'IOC', 'Root Certificate')
 
     

    ]



    
    # Assign events and notes values
    df['EventType'] = ''
    df['Notes'] = ''
    for condition, color, note in conditions_and_notes:
        df.loc[condition, 'EventType'] = color
        df.loc[condition, 'Notes'] = note

def style_conditional_colors(df):
    green_fill = 'background-color: #C6EFCE; color: #006100'
    red_fill = 'background-color: #E49EDD; color: #000000'
    yellow_fill = 'background-color: #FFEB9C; color: #9C5700'
    
    def _apply_styler(row):
        if row['EventType'] == 'IOC':
            return [green_fill] * len(row)
        elif row['EventType'] == 'CleanUp':
            return [red_fill] * len(row)
        elif row['EventType'] == 'Script Operations':
            return [yellow_fill] * len(row)
        else:
            return [''] * len(row)

    return df.style.apply(_apply_styler, axis=1)

# Read the Excel file into a pandas DataFrame
df = pd.read_excel('security_logs.xlsx')

# Update the 'Highlight' and 'Notes' columns based on conditions
update_highlight_and_notes(df)

# Apply conditional styling to a single DataFrame
df_style = style_conditional_colors(df)

# Save the styled DataFrame to an Excel file
output_file = "Security_Analysed.xlsx"
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    df_style.to_excel(writer, sheet_name='AnalysedLogs', index=False)

# Move the output file to the desired directory
output_dir = "./Analysis/"
os.makedirs(output_dir, exist_ok=True)
os.replace(output_file, os.path.join(output_dir, output_file))





def update_highlight_and_notes(df):
    # Define conditions and notes
    conditions_and_notes = [

        # Misc
        ((df['Id'] == 22) & (df['Message'].str.contains(r'google.ie')), 'IOC', ''),
        ((df['Id'] == 22) & (df['Message'].str.contains(r'download.sysinternals.com')), 'IOC', 'Sysinternals DNS Query'),
        ((df['Id'] == 3) & (df['Message'].str.contains(r'Image: C:\\Windows\\System32\\WindowsPowerShell\\')), 'IOC', 'PowerShell NetConnection'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'CommandLine: "C:\\Windows\\System32\\WScript.exe" "C:\\HEG\\Scripts\\')), 'Script Operations', ''),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'CommandLine: C:\\Windows\\system32\\cmd.exe /c ""C:\\HEG\\Scripts\\')), 'Script Operations', ''),

 



        # BITS
        ((df['Id'] == 7) & (df['Message'].str.contains(r'Image: C:\\Windows\\System32\\WindowsPowerShell\\')) & (df['Message'].str.contains(r'ImageLoaded: C:\\Windows\\System32\\BitsProxy.dll')), 'IOC', 'PowerShell Launching BITS'),
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-BITS\\')), 'IOC', 'BITS - Executable Detected'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-BITS')), 'IOC', 'BITS - File Create'),
        ((df['Id'] == 23) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-BITS')), 'CleanUp', 'BITS CleanUp'),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-BITS')), 'CleanUp', 'BITS CleanUp'),

        # Winvoke
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-WINVOKE\\')), 'IOC', 'Invoke-WebRequest - Executable Detected'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-WINVOKE')), 'IOC', 'Invoke-WebRequest - File Create'),
        ((df['Id'] == 23) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-WINVOKE')), 'CleanUp', 'Invoke-WebRequest - CleanUp'),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-WINVOKE')), 'CleanUp', 'Invoke-WebRequest - CleanUp'),


        # CURL
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-CURL\\')), 'IOC', 'CURL - Executable Detected'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-CURL')), 'IOC', 'CURL - File Create'),
        ((df['Id'] == 23) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-CURL')), 'CleanUp', 'CURL - CleanUp'),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-CURL')), 'CleanUp', 'CURL - CleanUp'),




        # RunDLL
        ((df['Id'] == 1) & (df['Message'].str.contains('rundll32.exe  devmgr.dll DeviceManager_Execute')), 'IOC', 'RunDLL'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'C:\\Windows\\system32\\devmgmt.msc /s')), 'IOC', 'RunDLL'),

        # WMIC
        ((df['Id'] == 1) & (df['Message'].str.contains('wmic  os get Caption,BuildNumber,Version,ServicePackMajorVersion')), 'IOC', 'WMIC'),
        ((df['Id'] == 1) & (df['Message'].str.contains('wmic  qfe list full')), 'IOC', 'WMIC'),

        # Encoded PowerShell
        ((df['Id'] == 1) & (df['Message'].str.contains('powershell  -exec bypass -e')), 'IOC', 'Encoded PowerShell Commands'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'C:\\Windows\\System32\\calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'C:\\Windows\\System32\\win32calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'IOC', 'Calc.exe Launched From Encoded PowerShell'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'IOC', 'Calc.exe created'),
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'IOC', 'Calc.exe created'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'IOC', ''),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\Staging\\Calc\\calc.exe')), 'CleanUp', ''),

        # Rogue Root Cert
        ((df['Id'] == 12) & (df['Message'].str.contains(r'\\Microsoft\\SystemCertificates\\\w+\\Certificates\\')), 'IOC', 'Root Certificate'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\Microsoft\\SystemCertificates\\\w+\\Certificates\\')), 'IOC', 'Root Certificate'),
        ((df['Id'] == 11) & (df['Message'].str.contains('COMPROMISED_CERTIFICATE.cer')), 'IOC', 'Root Certificate'),
        ((df['Id'] == 26) & (df['Message'].str.contains('COMPROMISED_CERTIFICATE.cer')), 'CleanUp', 'Root Certificate'),


        # Firewall - Create Exclusions
        ((df['Id'] == 1) & (df['Message'].str.contains('advfirewall firewall add rule name="HEG_Firewall-Exclusion-CMD" dir=in action=allow enable=yes')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Creation started'),

        # Firewall - Modifications
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')) & (~df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')) & (~df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-PS || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')) & (~df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')) & (~df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-JS || Modification in Registry'),

        # Firewall - Disable Exclusions
        ((df['Id'] == 1) & (df['Message'].str.contains('advfirewall firewall set rule name="HEG_Firewall-Exclusion-CMD" new enable=no')), 'IOC', 'Disable Inbound Firewall Exclusion'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-CMD')) & (df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Disabled in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')) & (df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-PS || Disabled in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-VBS')) & (df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-VBS || Disabled in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Firewall-Exclusion-JS')) & (df['Message'].str.contains('Active=FALSE')), 'IOC', 'HEG_Firewall-Exclusion-JS || Disabled in Registry'),
        
        
        # Firewall - Delete Exclusions
        ((df['Id'] == 1) & (df['Message'].str.contains('advfirewall firewall delete rule name="HEG_Firewall-Exclusion-CMD"')), 'IOC', 'HEG_Firewall-Exclusion-CMD || Deletion started'),
        ((df['Id'] == 12) & (df['Message'].str.contains(r'\\FirewallRules\\')), 'IOC', ''),
        


        # Firewall - Firewall Disabled
        ((df['Id'] == 1) & (df['Message'].str.contains('advfirewall set allprofiles state off')), 'IOC', 'Disable Windows Firewall'),
        ((df['Id'] == 1) & (df['Message'].str.contains('advfirewall set allprofiles state on')), 'CleanUp', 'Re-Enable Windows Firewall'),  





        # Scheduled Task - Creation
        ((df['Id'] == 1) & (df['Message'].str.contains(r'SCHTASKS  /CREATE /SC DAILY /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Creation Started'),
        ((df['Id'] == 11) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Created'),
        ((df['Id'] == 11) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Created'),
        ((df['Id'] == 11) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Created'),
        ((df['Id'] == 11) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Created'),



        # Scheduled Task - Modify
        ((df['Id'] == 1) & (df['Message'].str.contains(r'/CHANGE /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Modification Started'), 
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Modification in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Modification in Registry'),
        

        # Scheduled Task - Modify / Delete
        ((df['Id'] == 1) & (df['Message'].str.contains(r'SCHTASKS  /DELETE /TN "HEG_Scheduled-Task-CMD"')), 'IOC', 'HEG_Scheduled-Task-CMD || Deletion Started'), 
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Deleted in Registry'),
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Deleted in Registry'),
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Deleted in Registry'),
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Deleted in Registry'),
        ((df['Id'] == 26) & (df['Message'].str.contains('HEG_Scheduled-Task-CMD')), 'IOC', 'HEG_Scheduled-Task-CMD || Deleted'),
        ((df['Id'] == 26) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Deleted'),
        ((df['Id'] == 26) & (df['Message'].str.contains('HEG_Scheduled-Task-VBS')), 'IOC', 'HEG_Scheduled-Task-VBS || Deleted'),
        ((df['Id'] == 26) & (df['Message'].str.contains('HEG_Scheduled-Task-JS')), 'IOC', 'HEG_Scheduled-Task-JS || Deleted'),




        # Service Operations - Create
        ((df['Id'] == 1) & (df['Message'].str.contains('create HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('config HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Modification Started'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Service-CMD')) & (~df['Message'].str.contains('Updated_Tooling.exe')), 'IOC', 'HEG_Service-CMD || Modified in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Service-CMD')) & (df['Message'].str.contains('Updated_Tooling.exe')), 'IOC', 'HEG_Service-CMD || Tooling Updated in Registry'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Service-PS')) & (~df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-PS || Modified in Registry'),
        

        # Service Operations - Delete
        ((df['Id'] == 1) & (df['Message'].str.contains('delete HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Deletion Started'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Service-CMD')) & (df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-CMD || Deletion Started'),
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Service-CMD')), 'IOC', 'HEG_Service-CMD || Deleted'),
        ((df['Id'] == 13) & (df['Message'].str.contains('HEG_Service-PS')) & (df['Message'].str.contains('DeleteFlag')), 'IOC', 'HEG_Service-PS || Deletion Started'),
        ((df['Id'] == 12) & (df['Message'].str.contains('HEG_Service-PS')), 'IOC', 'HEG_Service-PS || Deleted'),




        # User Creation
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User-CMD')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-CMD || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User-PS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-PS || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User-JS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-JS || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User-VBS')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-VBS || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User-WMIC')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User-WMIC || Creation Started'),
        ((df['Id'] == 1) & (df['Message'].str.contains('HEG_User ')) & (df['Message'].str.contains(r'/add')), 'IOC', 'HEG_User || Creation Started'),


        # Registy - Create
        ((df['Id'] == 1) & (df['Message'].str.contains(r'REG  ADD HKEY_CURRENT_USER\\Console\\HEG_Registry-Key-CMD\\')), 'IOC', 'HEG_Registry-Key-CMD || Creation Started'),

        # Registy - Delete
        ((df['Id'] == 1) & (df['Message'].str.contains(r'REG  DELETE HKEY_CURRENT_USER\\Console\\HEG_Registry-Key-CMD\\')), 'IOC', 'HEG_Registry-Key-CMD || Deletion Started'),
       



        # BruteForce
        ((df['Id'] == 1) & (df['Message'].str.contains(r'\\Tools\\psexec  -u Administrator -p password')), 'IOC', 'Bruteforce Against Admin Account'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\Sysinternals\\PsExec\\EulaAccepted')), 'IOC', ''),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\CurrentVersion\\Time Zones\\')), 'IOC', 'TimeZone Change'),

        # Searching for .key files
        ((df['Id'] == 1) & (df['Message'].str.contains(r'dir c:\\Users\\Public /b /s .key')), 'IOC', 'Search for .key files'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'findstr  /e .key')), 'IOC', 'Findstr launched'),

        # Exfiltration - FTP
        ((df['Id'] == 3) & (df['Message'].str.contains(r'DestinationPort: 21')), 'IOC', 'FTP Connection Initiated'),
        ((df['Id'] == 22) & (df['Message'].str.contains(r'ftp.dlptest.com')), 'IOC', 'DNS Query with FTP Subdomain'),

        # Exfiltration - HTTP
        ((df['Id'] == 22) & (df['Message'].str.contains(r'pastebin.com')), 'IOC', 'DNS Query to Pastebin'),

        # Exfiltration - DNS
        ((df['Id'] == 22) & (df['Message'].str.contains(r'\w+.google.ie')), 'IOC', 'DNS Exfiltration'),

        # WinRM
        ((df['Id'] == 1) & (df['Message'].str.contains(r'quickconfig -q')), 'IOC', 'WinRM'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'sc  stop winrm')), 'CleanUp', 'WinRM Removal'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'config winrm start= disabled')), 'CleanUp', 'WinRM Removal'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'WinRM')), 'IOC', ''),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'WinRM\\Start')), 'IOC', ''),

        # PSExec
        ((df['Id'] == 1) & (df['Message'].str.contains('ping google.ie')), 'IOC', 'PSExec'),
        ((df['Id'] == 1) & (df['Message'].str.contains('ping  google.ie')), 'IOC', 'PSExec'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'\\Windows\\PSEXESVC.exe')), 'IOC', 'PSExec'),        
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\PSEXESVC.exe'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\PSEXESVC-'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\PSEXEC-'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec'),
        ((df['Id'] == 11) & (df['Message'].str.contains(r'\\PsExec.exe'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec'),       
        ((df['Id'] == 12) & (df['Message'].str.contains(r'\\PSEXESVC')), 'IOC', 'PSExec'),        
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\PSEXESVC')), 'IOC', 'PSExec'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\PsExec.exe')), 'IOC', 'PSExec'),        
        ((df['Id'] == 17) & (df['Message'].str.contains(r'\\PSEXESVC.exe')), 'IOC', 'PSExec'),       
        ((df['Id'] == 18) & (df['Message'].str.contains(r'\\PSEXESVC')), 'IOC', 'PSExec'),        
        ((df['Id'] == 22) & (df['Message'].str.contains(r'\\PSEXESVC.exe')), 'IOC', 'DNS Query From PSExec'),
        ((df['Id'] == 22) & (df['Message'].str.contains(r'\\PsExec.exe')), 'IOC', 'DNS Query From PSExec'),      
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\PSEXESVC.exe')), 'CleanUp', 'PSExec Delete'),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\PsExec.exe')), 'CleanUp', 'PSExec Delete'),
        ((df['Id'] == 26) & (df['Message'].str.contains(r'\\PSEXESVC-')), 'IOC', 'PSExec'),      
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\PSEXESVC.exe'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec Executable'),
        ((df['Id'] == 29) & (df['Message'].str.contains(r'\\PsExec.exe'))  & (~df['Message'].str.contains('ToolDownload-')), 'IOC', 'PSExec Executable'),



 
        # Log Resize
        ((df['Id'] == 13) & (df['Message'].str.contains(r'EventLog\\System\\MaxSize')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\EventLog\\Application\\MaxSize')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'\\EventLog\\Security\\MaxSize')), 'IOC', 'Event Log Resize'),

        # Log Disable
        ((df['Id'] == 13) & (df['Message'].str.contains(r'Microsoft-Windows-Bits-Client/Operational')), 'IOC', 'Event Log Enable/Disable'),
        ((df['Id'] == 13) & (df['Message'].str.contains(r'Microsoft-Windows-HelloForBusiness/Operational')), 'IOC', 'Event Log Enable/Disable'),        

        # Log Delete
        ((df['Id'] == 1) & (df['Message'].str.contains(r'/e:false')), 'IOC', 'Disable Logging'),
        ((df['Id'] == 1) & (df['Message'].str.contains(r'/e:true')), 'CleanUp', 'Re-Enable Logging'),
        ((df['Id'] == 1) & (df['Message'].str.contains('wevtutil.exe" cl ')), 'IOC', 'Log Cleared'),    

        # Shadow Copies
        ((df['Id'] == 1) & (df['Message'].str.contains(r'delete shadows /all /quiet')), 'IOC', 'Shadow Copies Deleted'),
        
        # Script Operations
        ((df['Id'] == 1) & (df['Message'].str.contains(r'^CommandLine: C:\\Windows\\system32\\cmd\.exe \/c ".*?"\s-Wait"')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Defense_Evasion\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Persistence\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Privilege_Escalation\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Credential_Access\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Exfiltration\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),        
        ((df['Id'] == 111) & (df['Message'].str.contains(r'\\Scripts\\Lateral_Movement\\')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'create shadow /for=C:')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', ''),
        ((df['Id'] == 111) & (df['Message'].str.contains('delete shadows')) & (df['Message'].str.contains('-Wait"')), 'IOC', 'Deleting Shadow Copies'),
        ((df['Id'] == 111) & (df['Message'].str.contains(r'cleanup.bat:')) & (df['Message'].str.contains('-Wait"')), 'Script Operations', '')

    ]



    
    # Assign events and notes values
    df['EventType'] = ''
    df['Notes'] = ''
    for condition, color, note in conditions_and_notes:
        df.loc[condition, 'EventType'] = color
        df.loc[condition, 'Notes'] = note

def style_conditional_colors(df):
    green_fill = 'background-color: #C6EFCE; color: #006100'
    red_fill = 'background-color: #E49EDD; color: #000000'
    yellow_fill = 'background-color: #FFEB9C; color: #9C5700'
    
    def _apply_styler(row):
        if row['EventType'] == 'IOC':
            return [green_fill] * len(row)
        elif row['EventType'] == 'CleanUp':
            return [red_fill] * len(row)
        elif row['EventType'] == 'Script Operations':
            return [yellow_fill] * len(row)
        else:
            return [''] * len(row)

    return df.style.apply(_apply_styler, axis=1)

# Read the Excel file into a pandas DataFrame
df = pd.read_excel('sysmon_logs.xlsx')

# Update the 'Highlight' and 'Notes' columns based on conditions
update_highlight_and_notes(df)

# Apply conditional styling to a single DataFrame
df_style = style_conditional_colors(df)

# Save the styled DataFrame to an Excel file
output_file = "Sysmon_Analysed.xlsx"
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    df_style.to_excel(writer, sheet_name='AnalysedLogs', index=False)

# Move the output file to the desired directory
output_dir = "./Analysis/"
os.makedirs(output_dir, exist_ok=True)
os.replace(output_file, os.path.join(output_dir, output_file))







def update_highlight_and_notes(df):
    # Define conditions and notes
    conditions_and_notes = [



        # Misc
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'https://download.sysinternals.com/files/PSTools.zip')), 'IOC', 'Sysinternals'),

        # BITS
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'system32\\WindowsPowerShell\\v1.0\\Modules\\BitsTransfer')), 'IOC', 'BITS'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Start-BitsTransfer')), 'IOC', 'BITS Transfer Start'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('Start-BitsTransfer')), 'IOC', 'BITS Transfer Start'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'\\Staging\\ToolDownload-BITS')), 'IOC', 'BITS'),

        # Winvoke
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'ToolDownload-WINVOKE')), 'IOC', 'Invoke WebRequest'),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'ToolDownload-WINVOKE')), 'IOC', 'Invoke WebRequest'),

        # CURL
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'ToolDownload-CURL')), 'IOC', 'CURL'),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'ToolDownload-CURL')), 'IOC', 'CURL'),

        # Encoded PowerShell
        ((df['Id'] == 4103) & (df['Message'].str.contains('powershell -exec bypass -e')), 'IOC', 'Encoded PowerShell command'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('powershell -exec bypass -e')), 'IOC', 'Encoded PowerShell command'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'\\Staging\\Calc')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'\\Staging\\Calc')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'calc.exe')), 'IOC', ''),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'calc.exe')) & (~df['Message'].str.contains('password is incorrect')), 'IOC', ''),

        # Rogue Root Cert
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'"New-SelfSignedCertificate"')), 'IOC', 'New Certificate'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'"Export-Certificate"')), 'IOC', 'Export Certificate'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'"Import-Certificate"')), 'IOC', 'Import Certificate'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('COMPROMISED_CERTIFICATE')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'\$rootCert = New-SelfSignedCertificate -CertStoreLocation cert:\\LocalMachine\\My -DnsName "COMPROMISED_CERTIFICATE"')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'{\$_.Subject -eq "CN=COMPROMISED_CERTIFICATE"}')), 'IOC', ''),




        # Firewall Operations - MISC

        ((df['Id'] == 4103) & (df['Message'].str.contains('Set-NetFirewallRule')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', ''),
        
        # Firewall Operations - Disable
        ((df['Id'] == 4104) & (df['Message'].str.contains('Disable-NetFirewallRule -DisplayName "HEG_Firewall-Exclusion-PS"')), 'IOC', 'HEG_Firewall-Exclusion-PS || Disabling Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Disable-NetFirewallRule')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Disable Command Processed'),

        # Firewall Operations - Delete
        ((df['Id'] == 4104) & (df['Message'].str.contains('Remove-NetFirewallRule -DisplayName "HEG_Firewall-Exclusion-PS"')), 'IOC', 'HEG_Firewall-Exclusion-PS || Deletion Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Remove-NetFirewallRule')) & (df['Message'].str.contains('HEG_Firewall-Exclusion-PS')), 'IOC', 'HEG_Firewall-Exclusion-PS || Delete Command Processed'),

        # Firewall Operations - Disable Windows Firewall
        ((df['Id'] == 4104) & (df['Message'].str.contains('netsh advfirewall set allprofiles state off')), 'IOC', 'Disable Windows Firewall'),
        
        


        #User Operations - User Create
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-LocalUser\): "New-LocalUser"')) & (df['Message'].str.contains('HEG_User-PS')), 'IOC', 'HEG_User-PS || Creation Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-LocalUser\): "New-LocalUser"')) & (df['Message'].str.contains('HEG_User-WMIC')), 'IOC', 'HEG_User-WMIC || Creation Started'),


        # User Operations - Non-Expiring Password
        ((df['Id'] == 4104) & (df['Message'].str.contains('Set-LocalUser -Name "HEG_User" -PasswordNeverExpires:')), 'IOC', 'HEG_User || Updating to Non-Expiring Password'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'ParameterBinding\(Set-LocalUser\): name="PasswordNeverExpires"; value="True"')), 'IOC', 'HEG_User || Command Process for Non-Expiring Password'),


        # User Operations - Promote User to Admin/RDP
        ((df['Id'] == 4104) & (df['Message'].str.contains('groups = "Administrators", "Remote Desktop Users"')) & (df['Message'].str.contains('HEG_User')), 'IOC', 'HEG_User || Updating Group Membership Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Add-LocalGroupMember')) & (df['Message'].str.contains('Remote Desktop Users')), 'IOC', 'HEG_User || Added to RDP'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Add-LocalGroupMember')) & (df['Message'].str.contains('Administrators')), 'IOC', 'HEG_User || Added to Administrators'),


        # User Operations - Disable user
        ((df['Id'] == 4104) & (df['Message'].str.contains('Disable-LocalUser -Name "HEG_User"')), 'IOC', 'HEG_User || Disabling Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Disable-LocalUser\): "Disable-LocalUser"')), 'IOC', 'HEG_User || Disable Command Processed'),





        # Service Operations - Create Service
        ((df['Id'] == 4104) & (df['Message'].str.contains('New-Service -Name "HEG_Service-PS" -BinaryPathName')), 'IOC', 'HEG_Service-PS || Creation Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-Service\): "New-Service"')), 'IOC', 'HEG_Service-PS || Creation Command Processed'),


        # Service Operations - Disable Service
        ((df['Id'] == 4104) & (df['Message'].str.contains('Set-Service -Name "HEG_Service-PS" -StartupType Disabled')), 'IOC', 'HEG_Service-PS || Disabling Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Set-Service\): "Set-Service"')) & (df['Message'].str.contains('HEG_Service-PS')) & (df['Message'].str.contains('value="Disabled"')), 'IOC', 'HEG_Service-PS || Disable Command Processed'),



        # Service Operations - Delete Service
        ((df['Id'] == 4104) & (df['Message'].str.contains('Stop-Service -Name "HEG_Service-PS"')), 'IOC', 'HEG_Service-PS || Deletion Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Stop-Service\): "Stop-Service"')) & (df['Message'].str.contains('HEG_Service-PS')), 'IOC', 'HEG_Service-PS || Stopping Service Command Processed'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'ParameterBinding\(Get-WmiObject\):')) & (df['Message'].str.contains('HEG_Service-PS')), 'IOC', 'HEG_Service-PS || Service Deletion Command Processed'),



        # Scheduled Task - Create Task
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-ScheduledTaskAction\): "New-ScheduledTaskAction"')) & (df['Message'].str.contains('Legacy_Tooling.exe')), 'IOC', 'HEG_Scheduled-Task-PS || Creation Command Processed'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Register-ScheduledTask\): "Register-ScheduledTask"')) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Register Command Processed'),


        # Scheduled Task - Modify Task
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-ScheduledTaskAction\): "New-ScheduledTaskAction"')) & (df['Message'].str.contains('Updated_Tooling.exe')), 'IOC', 'HEG_Scheduled-Task-PS || Modification Command Processed'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-ScheduledTaskTrigger\): "New-ScheduledTaskTrigger"')), 'IOC', 'HEG_Scheduled-Task-PS || Modification Command Processed'),



        # Scheduled Task - Disable Task
        ((df['Id'] == 4104) & (df['Message'].str.contains('Disable-ScheduledTask -TaskName HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Disabling Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Disable-ScheduledTask\): "Disable-ScheduledTask"')) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Disable Command Processed'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('Unregister-ScheduledTask -TaskName HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Unregistering Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(Unregister-ScheduledTask\): "Unregister-ScheduledTask"')) & (df['Message'].str.contains('HEG_Scheduled-Task-PS')), 'IOC', 'HEG_Scheduled-Task-PS || Unregister Command Processed'),



        # Registry - Create Key
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'New-Item -Path HKCU:\\Console\\HEG_Registry-Key-PS -Force')), 'IOC', 'HEG_Registry-Key-PS || Creation Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-Item\): "New-Item"')) & (df['Message'].str.contains('HEG_Registry-Key-PS')), 'IOC', 'HEG_Registry-Key-PS || RegKey Creation Command Processed'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'CommandInvocation\(New-ItemProperty\)')) & (df['Message'].str.contains('HEG_Registry-Key-PS')), 'IOC', 'HEG_Registry-Key-PS || RegKey Value Set Command Processed'),


        # Registry - Modify Key
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'Set-ItemProperty -Path HKCU:\\Console\\HEG_Registry-Key-PS -Name HEG -Value "Updated"')), 'IOC', 'HEG_Registry-Key-PS || Modification Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'\(Set-ItemProperty\):')) & (df['Message'].str.contains(r'value="HKCU:\\Console\\HEG_Registry-Key-PS"')), 'IOC', 'HEG_Registry-Key-PS || Modification Command Processed'),


        # Registry - Delete Key
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'Remove-Item -Path HKCU:\\Console\\HEG_Registry-Key-PS -Recurse -Force')), 'IOC', 'HEG_Registry-Key-PS || Deletion Started'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'\(Remove-Item\):')) & (df['Message'].str.contains(r'value="HKCU:\\Console\\HEG_Registry-Key-PS"')), 'IOC', 'HEG_Registry-Key-PS || Deletion Command Processed'),




        # BruteForce
        ((df['Id'] == 4103) & (df['Message'].str.contains('The user name or password is incorrect.')), 'IOC', 'Bad Password Error'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('The referenced account is currently locked out and may not')), 'IOC', 'Account is Locked Out'),
        ((df['Id'] == 4100) & (df['Message'].str.contains('The user name or password is incorrect')), 'IOC', 'Bad Password Error'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Get-TimeZone')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains('Get-TimeZone')), 'IOC', ''),
        ((df['Id'] == 4103) & (df['Message'].str.contains('ConvertTo-SecureString')), 'IOC', 'Converting Password to Secure String'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('ConvertTo-SecureString')), 'IOC', 'Converting Password to Secure String'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Guest, System.Security.SecureString')), 'IOC', 'Sending Password'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('randomDate')), 'IOC', ''),
        ((df['Id'] == 4103) & (df['Message'].str.contains('randomDate')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains('Set-Date')), 'IOC', 'Resetting Date'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Set-Date')), 'IOC', 'Resetting Date'),

        # Exfiltration - FTP
        ((df['Id'] == 4103) & (df['Message'].str.contains('name="ArgumentList"; value="dlpuser')), 'IOC', 'FTP'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('FTP connection successful. Server response: 150 Here comes the directory listing')), 'IOC', 'FTP Connection Successful'),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'\$ftpServer =')), 'IOC', 'FTP'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('dlpuser')), 'IOC', 'FTP'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('System.Net.WebClient')), 'IOC', 'FTP'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('Random_Data.txt')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains('Random_Data.txt')), 'IOC', ''),
        ((df['Id'] == 4103) & (df['Message'].str.contains('test.txt')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains('test.txt')), 'IOC', ''),

        # Exfiltration - HTTP
        ((df['Id'] == 4103) & (df['Message'].str.contains('pastebin.com')), 'IOC', 'PasteBin'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('pastebin.com')), 'IOC', 'PasteBin'),
        ((df['Id'] == 4103) & (df['Message'].str.contains('TABvAHIAZQB')), 'IOC', ''),
        ((df['Id'] == 4104) & (df['Message'].str.contains('TABvAHIAZQB')), 'IOC', ''),

        # Exfiltration - DNS
        ((df['Id'] == 4103) & (df['Message'].str.contains('google.ie'))  & (df['Message'].str.contains('Test-Connection')), 'IOC', 'DNS Exfiltration'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('google.ie'))  & (df['Message'].str.contains('Test-Connection')), 'IOC', 'DNS Exfiltration'),

        # PSExec
        ((df['Id'] == 4103) & (df['Message'].str.contains('PsExec')), 'IOC', 'PsExec'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('PsExec')), 'IOC', 'PsExec'),

        # Log Resize
        ((df['Id'] == 4104) & (df['Message'].str.contains('$Logs = "System", "Application", "Security"')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'Limit-EventLog')), 'IOC', 'Event Log Resize'),
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'Limit-EventLog')), 'IOC', 'Event Log Resize'),
              
        # Log Disable
        ((df['Id'] == 4104) & (df['Message'].str.contains('wevtutil.exe" sl')), 'IOC', 'Log Disabled'),
        ((df['Id'] == 4104) & (df['Message'].str.contains('e:false')), 'IOC', 'Log Disable'),

        # Log Delete
        ((df['Id'] == 4104) & (df['Message'].str.contains('wevtutil.exe cl')), 'IOC', 'Log Cleared'),    

        # Shadow Copies
        ((df['Id'] == 4104) & (df['Message'].str.contains(r'vssadmin.exe" -ArgumentList "delete shadows /all /quiet')), 'IOC', 'Shadow Copies Deleted'),
        ((df['Id'] == 4103) & (df['Message'].str.contains(r'value="delete shadows /all /quiet')), 'IOC', 'Shadow Copies Deleted'),
        
    ]



    
    # Assign events and notes values
    df['EventType'] = ''
    df['Notes'] = ''
    for condition, color, note in conditions_and_notes:
        df.loc[condition, 'EventType'] = color
        df.loc[condition, 'Notes'] = note

def style_conditional_colors(df):
    green_fill = 'background-color: #C6EFCE; color: #006100'
    red_fill = 'background-color: #E49EDD; color: #000000'
    yellow_fill = 'background-color: #FFEB9C; color: #9C5700'
    
    def _apply_styler(row):
        if row['EventType'] == 'IOC':
            return [green_fill] * len(row)
        elif row['EventType'] == 'CleanUp':
            return [red_fill] * len(row)
        elif row['EventType'] == 'Script Operations':
            return [yellow_fill] * len(row)
        else:
            return [''] * len(row)

    return df.style.apply(_apply_styler, axis=1)

# Read the Excel file into a pandas DataFrame
df = pd.read_excel('powershell_operational_logs.xlsx')

# Update the 'Highlight' and 'Notes' columns based on conditions
update_highlight_and_notes(df)

# Apply conditional styling to a single DataFrame
df_style = style_conditional_colors(df)

# Save the styled DataFrame to an Excel file
output_file = "PowerShell_Analysed.xlsx"
with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
    df_style.to_excel(writer, sheet_name='AnalysedLogs', index=False)

# Move the output file to the desired directory
output_dir = "./Analysis/"
os.makedirs(output_dir, exist_ok=True)
os.replace(output_file, os.path.join(output_dir, output_file))



