import re
import sqlite3
import winreg

key_paths = [
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Component Based Servicing\\Packages",
    "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products",
    "SOFTWARE\\WOW6432Node\\Microsoft\\Updates"
]


# def search_for_hotfixes(hotfix_list, key_path):
#     try:
#         key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
#         for i in range(winreg.QueryInfoKey(key)[0]):
#             sub_key_name = winreg.EnumKey(key, i)
#             sub_key_path = f"{key_path}\\{sub_key_name}"
#             if sub_key_name.startswith("KB") and sub_key_name[2:].isdigit():
#                 if sub_key_name not in hotfix_list:
#                     hotfix_list.append(sub_key_name[2:])
#             search_for_hotfixes(hotfix_list, sub_key_path)

#         for i in range(winreg.QueryInfoKey(key)[1]):
#             value_name, value_data, value_type = winreg.EnumValue(key, i)
#             if value_name == "DisplayName" and isinstance(value_data, str) and re.search(r"KB\d+", value_data):
#                 print(value_data)
#                 hotfix_name = re.search(r"KB(\d+)", value_data).group(1)
#                 if hotfix_name not in hotfix_list:
#                     hotfix_list.append(hotfix_name)
#     except WindowsError:
#         pass

def extractHFValue(input):
    KB_FORMAT_REGEX_STR = r"(KB[0-9]{6,})"
    rex = re.compile(KB_FORMAT_REGEX_STR)
    ret = ""
    input = input.upper()
    match = rex.search(input)

    if match:
        ret = match.group(1)

    return ret


def enumerateKeys(root, callback):
    for i in range(winreg.QueryInfoKey(root)[0]):
        subKey = winreg.EnumKey(root, i)
        callback(subKey)


def getStringValue(key, valueName):
    return winreg.QueryValueEx(key, valueName)


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


def getHotFixFromReg(key, subKey, hotfixes):
    try:
        root = winreg.OpenKey(
            key, subKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)

        def callback(package):
            if package.startswith("Package_"):
                hfValue = extractHFValue(package)
                if hfValue:
                    hotfixes.add(hfValue[2:])
                elif "RollupFix" in package:
                    value = ""
                    packageReg = winreg.OpenKey(
                        key, subKey + "\\" + package, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    try:
                        value, _ = winreg.QueryValueEx(
                            packageReg, "InstallLocation")
                    except WindowsError:
                        pass
                    if value:
                        rollUpValue = extractHFValue(value)
                        if rollUpValue:
                            hotfixes.add(rollUpValue[2:])

        enumerateKeys(root, callback)
    except WindowsError:
        pass


def getHotFixFromRegNT(key, subKey, hotfixes):
    try:
        def callback(package):
            hfValue = extractHFValue(package)
            if hfValue:
                hotfixes.add(hfValue[2:])

        root = winreg.OpenKey(
            key, subKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        enumerateKeys(root, callback)
    except WindowsError:
        pass


def getHotFixFromRegWOW(key, subKey, hotfixes):
    try:
        def callback(packageKey):
            def callbackKey(package):
                hfValue = extractHFValue(package)
                if hfValue:
                    hotfixes.add(hfValue[2:])

            packageReg = winreg.OpenKey(
                key, subKey + "\\" + packageKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            enumerateKeys(packageReg, callbackKey)

        root = winreg.OpenKey(
            key, subKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        enumerateKeys(root, callback)
    except WindowsError:
        pass


def getHotFixFromRegProduct(key, subKey, hotfixes):
    try:
        def callback(packageKey):
            def callbackKey(package):
                if package.startswith("InstallProperties"):
                    packageReg = winreg.OpenKey(
                        key, subKey + "\\" + packageKey + "\\" + package, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    value, _ = getStringValue(packageReg, "DisplayName")
                    hfValue = extractHFValue(value)
                    if hfValue:
                        hotfixes.add(hfValue[2:])
                elif package.startswith("Patches"):
                    def callbackPatch(packagePatch):
                        packageReg = winreg.OpenKey(
                            key, subKey + "\\" + packageKey + "\\" + package + "\\" + packagePatch, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                        value, _ = getStringValue(packageReg, "DisplayName")
                        hfValue = extractHFValue(value)
                        if hfValue:
                            hotfixes.add(hfValue[2:])

                    rootPatch = winreg.OpenKey(
                        key, subKey + "\\" + packageKey + "\\" + package, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
                    enumerateKeys(rootPatch, callbackPatch)

            rootKey = winreg.OpenKey(
                key, subKey + "\\" + packageKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
            enumerateKeys(rootKey, callbackKey)

        root = winreg.OpenKey(
            key, subKey, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY)
        enumerateKeys(root, callback)
    except WindowsError:
        pass


def search_hotfixes_in_file(hotfixes, file_path):
    missing_hotfixes = set()

    with open(file_path, 'r') as file:
        file_content = file.read()

        for hotfix in hotfixes:
            if hotfix not in file_content:
                missing_hotfixes.add(hotfix)

    for missing_hotfix in missing_hotfixes:
        print(f"Hotfix '{missing_hotfix}' not found in the file.")


def search_for_hotfixes(hotfixes):

    key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
    getHotFixFromReg(winreg.HKEY_LOCAL_MACHINE, key_path, hotfixes)

    key_path = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Installer\\UserData\\S-1-5-18\\Products"
    getHotFixFromRegProduct(winreg.HKEY_LOCAL_MACHINE, key_path, hotfixes)

    key_path = r"SOFTWARE\\WOW6432Node\\Microsoft\\Updates"
    getHotFixFromRegWOW(winreg.HKEY_LOCAL_MACHINE, key_path, hotfixes)

    key_path = r"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\HotFix"
    getHotFixFromRegNT(winreg.HKEY_LOCAL_MACHINE, key_path, hotfixes)
