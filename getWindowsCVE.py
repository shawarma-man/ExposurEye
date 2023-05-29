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

cpe_string = "cpe:2.3:o:microsoft:windows_{}:{}:*:*:*:*:*:*:*"
cpe_string2 = "cpe:2.3:o:microsoft:windows_{}:{}:*:*:*:*:*:{}:*"

cve_patch_pair = """
SELECT C.CVE_ID,P.Patch
FROM NVD_CVE_MATCH D
INNER JOIN NVD_CVE_CONFIGURATION E ON D.NVD_CVE_CONFIGURATION_ID = E.ID
INNER JOIN NVD_CVE C ON E.NVD_CVE_ID = C.ID
INNER JOIN MSU P ON C.CVE_ID = P.CVEID
WHERE (URI = ? OR URI = ?)
AND VULNERABLE == '1' 
AND P.PRODUCT = ?;"""


def getVersion():

    key_path = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
    value_name = "DisplayVersion"

    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
        display_version = winreg.QueryValueEx(key, value_name)[0]
    arch = platform.machine()
    os_release = platform.release()
    if arch == "AMD64":
        arch = "x64-based Systems"
        cpe_arch = "x64"
    elif arch == "ARM64":
        arch = "ARM64-based Systems"
        cpe_arch = "arm64"
    else:
        arch = "32-bit Systems"
        cpe_arch = "x86"

    return display_version, arch, os_release, cpe_arch


def getWindowsCVE():

    version, arch, release, cpe_arch = getVersion()
    installed_hotfixes = set()
    search_for_hotfixes(installed_hotfixes)
    dependencies = find_dependencies(installed_hotfixes)
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
        c.execute(cve_patch_pair,
                  (cpe_string.format(release, version.lower()), cpe_string2.format(release, version.lower(), cpe_arch), f'Windows {release} Version {version} for {arch}'))
        for row in c.fetchall():
            if row[1] not in installed_hotfixes:
                cve_details = get_cve_details(row[0], row[1])
                cve_item[row[0]] = cve_details
    cve_details_list = {f'Windows {release}': cve_item}

    filename = 'cve_details.json'
    if os.path.exists(os.path.join(os.getcwd(), filename)):
        with open(filename, 'r') as f:
            existing_data = json.load(f)
            if f'Windows {release}' in existing_data:
                existing_cve_item = existing_data[f'Windows {release}']
                existing_cve_item.update(cve_item)
                cve_details_list = {f'Windows {release}': existing_cve_item}

    with open(filename, 'w') as f:
        json.dump(cve_details_list, f, indent=4)
