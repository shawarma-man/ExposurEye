import json
import os
from cpe_helper import get_best_cpe
from getCVEDetails import append_cve_details
from getWindowsCVE import getVersion
from sanitize import *
import subprocess
from custom_prompts import custom_prompt
import re

# these values can be variant for each PC and should be changed accordingly or extended
# these values represent the programs where the vendor is a part of the product name so it should not be removed
whitelist = ["python", "apache netbeans", "openssl", "power",
             "postman", "gom", "opera", "mongodb", "github", "HI-TECH"]
# regex to match edition formats
Edition_pattern = r"\b([a-zA-Z]+) Edition\b"
# regex to match version numbers formats
version_pattern = r'\b\w*[a-zA-Z]\w*[.\d]+\w*\b|\b\w*[.\d]+\w*[a-zA-Z]\w*\b|\d+(\.\d+)+'

system_cpes = ["cpe:2.3:o:microsoft:windows_10:{}:*:*:*:*:*:*:*",
               "cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*", "cpe:2.3:o:microsoft:windows_10:*:*:*:*:*:*:*:*"]
version, arch, release, cpe_arch = getVersion()


def getAppsCPE():
    apps_data = json.load(open('apps.json'))
    for app in apps_data:
        if not app.get("Version") or not app.get("ProgramName") or not app.get("Vendor"):
            continue
        version_parts = app.get("Version").split(".")
        version = ".".join(version_parts[:3])
        cpe_str, score = get_best_cpe(app.get("ProgramName").replace(
            " ", "_"), app.get("Vendor").replace(" ", "_"), version)
        if score < 0.6:
            app["cpe"] = "N/A"
            print(custom_prompt(
                'warning', f"No appropriate matches for: {app.get('ProgramName')}\n"))
        elif score < 0.9 and score >= 0.6:
            print(custom_prompt(
                'warning', f"Found possible match for: {app.get('ProgramName')}\n"))
            choice = input(custom_prompt(
                'warning', f"Would you like to use {cpe_str}? (y/n) Default: y\n")).lower()
            if choice not in ['n', 'no']:
                app["cpe"] = cpe_str
            else:
                app["cpe"] = "N/A"
        else:
            app["cpe"] = cpe_str
            print(custom_prompt('information',
                  f"Found appropriate match for: {app.get('ProgramName')}\n"))

    with open("apps.json", "w") as outfile:
        json.dump(apps_data, outfile, indent=4)


def getAppsCVE():
    # Save installed apps to temp file
    with open('temp.txt', 'w') as file:
        subprocess.run(
            ['powershell', '-File', 'Get-RemoteProgram.ps1'], stdout=file)

    with open('temp.txt') as file:
        lines = [line.strip() for line in file if ":" in line]

    programs = []
    program = {}
    for index, line in enumerate(lines):
        # Remove null characters and unnecessary characters
        prop, val = line.split(":", 1)
        prop = prop.replace('\0', '').strip()
        val = val.replace('\0', '').strip()
        # Extract Edition from ProgramName field
        if (prop == "ProgramName"):
            Edition_match = re.search(Edition_pattern, val)
            if Edition_match:
                program["Edition"] = Edition_match.group(1)
            else:
                program["Edition"] = "N/A"
        # remove blacklist words from program name and vendor
        if (prop == "Vendor" or prop == "ProgramName"):
            val = sanitize(val.strip())

        # Extract Version from ProgramName field
        if prop == "Version":
            match = re.search(version_pattern, program.get("ProgramName"))
            if match:
                tmp = match.group()
                if ((len(val) > len(tmp) and len(tmp) > 0) or len(val) == 0):
                    val = tmp
                # program["ProgramName"] = (program.get("ProgramName").replace(tmp, "")).strip()
                program["ProgramName"] = re.sub(
                    '\s+', ' ', program.get("ProgramName").replace(tmp, "")).strip()

        program[prop] = val

        # Only include non-system components, and ignore those with Microsoft vendor name and those in the whitelist
        if prop == "SystemComponent":
            if not program.get("SystemComponent") and program.get("Vendor").lower() != "microsoft" and "Windows Driver Package" not in program.get("ProgramName"):
                # Remove vendor name from program name unless it is part of the program name
                if (program.get("Vendor") in program.get("ProgramName") and program.get("Vendor") != program.get("ProgramName") and program.get("Vendor").lower() not in whitelist):
                    program["ProgramName"] = (program.get("ProgramName").replace(
                        program.get("Vendor"), "")).strip()

                if program.get("Version").replace(".", "") in program.get("ProgramName"):
                    program["ProgramName"] = (program.get("ProgramName").replace(
                        program.get("Version").replace(".", ""), "")).strip()

                programs.append(program)
                program = {}

    # Include last program in cases where SystemComponent field is not included
    if not program.get("SystemComponent") and program.get("ProgramName"):
        programs.append(program)

    for i in system_cpes:
        program["Edition"] = "N/A"
        program["ProgramName"] = ("Windows")
        program["Vendor"] = "Microsoft"
        program["Version"] = ""
        program["cpe"] = i.format(version)
        programs.append(program)
        program = {}
    with open("apps.json", "w") as outfile:
        json.dump(programs, outfile, indent=4)

    print(custom_prompt('information', "Saved installed application to apps.json...\n"))
    os.remove('temp.txt')

    print(custom_prompt('information',
          "Searching for suitable CPE strings for installed applications...\n"))
    getAppsCPE()

    print(custom_prompt('information',
          "Searching for CVEs for installed applications...\n"))
    append_cve_details()
