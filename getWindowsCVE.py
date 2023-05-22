import json
import os
from pathlib import Path
import platform
import re
import sqlite3
import subprocess
import winreg
from tqdm import tqdm
from custom_prompts import custom_prompt
from getCVEDetails import get_cve_details
from getHotfixes import find_dependencies, search_for_hotfixes


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


def getWindowsCVE():
    version, arch = getVersion()

    installed_hotfixes = set()
    search_for_hotfixes(installed_hotfixes)
    with open('Original_installed_hotfixes.txt', 'w') as f:
        f.write('\n'.join(installed_hotfixes))
    dependencies = find_dependencies(installed_hotfixes)
    print(len(dependencies))
    installed_hotfixes = installed_hotfixes.union(dependencies)
    installed_hotfixes = list(set(installed_hotfixes))

    with open('installed_hotfixes.txt', 'w') as f:
        f.write('\n'.join(installed_hotfixes))

    print(custom_prompt('information',
          f'Checking for vulnerabilities on Windows {version} {arch}...\n'))
    cve_details_list = []
    cve_item = {}
    db_path = Path('shawarma.db')
    with sqlite3.connect(str(db_path)) as conn:
        c = conn.cursor()
        c.execute('''SELECT CVEID, PRODUCT, PATCH, TITLE, URL, restart_required, subtype FROM msu WHERE PRODUCT = ?''',
                  (f'Windows 10 Version {version} for {arch}',))
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
