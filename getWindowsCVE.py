import json
import os
from pathlib import Path
import platform
import sqlite3
import subprocess
import winreg
from tqdm import tqdm
from custom_prompts import custom_prompt
from getCVEDetails import get_cve_details

#List of registry keys to search for hotfixes
key_paths = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Updates"
]

def getVersion():

    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    value_name = "DisplayVersion"

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        display_version = winreg.QueryValueEx(key, value_name)[0]
    arch = platform.machine()
    if arch == "AMD64":
        arch = "x64-based Systems"
    elif arch == "ARM64":
        arch = "ARM64-based Systems"
    else:
        arch = "32-bit Systems"

    return display_version, arch




                    
def search_for_hotfixes(hotfix_list, key_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        for i in range(winreg.QueryInfoKey(key)[0]):
            sub_key_name = winreg.EnumKey(key, i)
            sub_key_path = f"{key_path}\\{sub_key_name}"
            if sub_key_name.startswith("KB") and sub_key_name[2:].isdigit():
                if sub_key_name not in hotfix_list:
                    hotfix_list.append(sub_key_name[2:])
            search_for_hotfixes(hotfix_list, sub_key_path)

        for i in range(winreg.QueryInfoKey(key)[1]):
            value_name, value_data, value_type = winreg.EnumValue(key, i)
            if isinstance(value_data, str) and value_data.startswith("KB") and value_data[2:].isdigit():
                if value_data not in hotfix_list:
                    hotfix_list.append(value_data[2:])
    except WindowsError:
        pass

def find_dependencies(hotfixes):
    # Connect to the database
    conn = sqlite3.connect('shawarma.db')
    c = conn.cursor()

    # Create a set to store the dependencies
    dependencies = set()

    # Recursively find all the dependencies
    def find_dependencies_rec(hotfix):
        # Get the dependencies of the hotfix
        c.execute('SELECT PATCH FROM msu_supersedence WHERE Super = ?', (hotfix,))
        patches = c.fetchall()
        for patch in patches:
            if patch[0] not in dependencies:
                dependencies.add(patch[0])
                find_dependencies_rec(patch[0])

    # Iterate through the input hotfixes and find their dependencies
    for hotfix in hotfixes:
        dependencies.add(hotfix)
        find_dependencies_rec(hotfix)

    # Close the database connection
    conn.close()

    # Return the set of dependencies
    return dependencies


def getWindowsCVE():
    version,arch = getVersion()
    
    installed_hotfixes = []
    for line in tqdm(subprocess.check_output('wmic qfe get hotfixid').decode().splitlines(), desc='Getting installed hotfixes'):
        if line.startswith('KB'):
            if line not in installed_hotfixes:
                installed_hotfixes.append(line.strip()[2:])
    for key_path in key_paths:
        search_for_hotfixes(installed_hotfixes, key_path)
    dependencies = find_dependencies(installed_hotfixes)
    installed_hotfixes += dependencies
    installed_hotfixes = list(set(installed_hotfixes))
    
    with open('installed_hotfixes.txt', 'w') as f:
        f.write('\n'.join(installed_hotfixes))
    
    print(custom_prompt('information', f'Checking for vulnerabilities on Windows {version} {arch}...\n'))
    cve_details_list = []
    cve_item = {}
    db_path = Path('shawarma.db')
    with sqlite3.connect(str(db_path)) as conn:
        c = conn.cursor()
        c.execute('''SELECT CVEID, PRODUCT, PATCH, TITLE, URL, restart_required, subtype FROM msu WHERE PRODUCT = ?''', (f'Windows 10 Version {version} for {arch}',))
        for row in c.fetchall():
            if row[2] not in installed_hotfixes:
                print(row[0])
                cve_details = get_cve_details(row[0])
                cve_item[row[0]] = cve_details
    cve_details_list = {'Windows 10': cve_item}

    filename = 'cve_details.json'
    if os.path.exists(os.path.join(os.getcwd(), filename)):
        with open(filename, 'r') as f:
            existing_data = json.load(f)
            if 'Windows 10' in existing_data:
                existing_cve_item = existing_data['Windows 10']
                existing_cve_item.update(cve_item)
                cve_details_list = {'Windows 10': existing_cve_item}

    with open(filename, 'w') as f:
        json.dump(cve_details_list, f, indent=4)