import re
# this function is used to match the version format in the cpe string with the app version
def sanitize_cpe_string(cpe_str, app_version,app_edition):
    cpe_version = cpe_str.split(':')[5]
    # check if version in cpe string is a wildcard or dash
    if cpe_version == '*' or cpe_version == '-':
        version_str = app_version
    else:
        # get number of dots in cpe version place
        cpe_version_parts = cpe_str.split(':')[5].split('.')
        num_dots = len(cpe_version_parts) - 1
        
        # get truncated version string from app version
        app_version_parts = app_version.split('.')
        truncated_parts = app_version_parts[:num_dots+1]
        version_str = '.'.join(truncated_parts)
    
    # replace version place in cpe string
    parts = cpe_str.split(':')
    parts[5] = version_str
    if app_edition != "N/A":
        sw_edition = app_edition
    else:
        sw_edition = "*"
    sanitized_cpe_str = ':'.join(parts[:6]) + f':*:*:*:{sw_edition}:*:*:*'
    
    return sanitized_cpe_str

def sanitize(string):
    # Blacklist patterns
    blacklist = ["®","(TM)","(R)","Corporation", "Software", "Inc", "s.r.o.", "LLC", "Software", 
                "Co., Ltd.", "Co.", "Ltd.", "Ltd", "Software, Inc.", "Software Inc.",
                "Foundation", "Technologies Co.Ltd", "Technologies", "Co.Ltd", "& Company",
                ",", "Corp.", "and/or its affiliates", "Games", "Win64 Installer Team", "(64-bit)", 
                "(x64)","x64", "x86_64","64-bit", "Development Community","Development", "Development Team", "the", 
                ]

    pattern = re.compile("|".join(map(re.escape, blacklist)), flags=re.IGNORECASE)

    # sanitize blacklist strings
    sanitized_string = pattern.sub("", string)
    # remove "." which are not part of a version number
    sanitized_string = re.sub(r"(?<!\d)\.(?!\d)", "", sanitized_string)
    sanitized_string = re.sub(r"\b([a-zA-Z]+) Edition\b","", sanitized_string)
    # replace u char in utorrent
    sanitized_string = sanitized_string.replace('\u00e6','u').strip()
    # remove the word "ide" from string
    tmpex = re.compile(r"\bide\b", re.IGNORECASE)
    sanitized_string = tmpex.sub("", sanitized_string)
    return sanitized_string.strip()
