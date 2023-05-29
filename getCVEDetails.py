from pathlib import Path
import sqlite3
import json
from packaging import version
from custom_prompts import custom_prompt
from sanitize import sanitize_cpe_string

same_parent_query = """
WITH RECURSIVE
  -- Start with the given ID, only if parent is not 0
  parents(id, nvd_cve_id, parent, operator) AS (
    SELECT id, nvd_cve_id, parent, operator
    FROM NVD_CVE_CONFIGURATION
    WHERE id = ? AND parent != 0
    UNION ALL
    -- Recursively join to the parent rows
    SELECT n.id, n.nvd_cve_id, n.parent, n.operator
    FROM NVD_CVE_CONFIGURATION n
    JOIN parents p ON n.id = p.parent
  )
-- Select all rows with the same parent as the given ID, excluding the row with the given ID
SELECT *
FROM NVD_CVE_CONFIGURATION
WHERE parent IN (SELECT id FROM parents)
  AND id != ?
"""

cve_details_query_ConfID = """
SELECT c.CVE_ID, c.DESCRIPTION, m.BASE_SCORE, m.BASE_SEVERITY, m.VECTOR_STRING
FROM NVD_CVE c
INNER JOIN NVD_METRIC_CVSS m ON m.NVD_CVE_ID = c.id
INNER JOIN NVD_CVE_CONFIGURATION nvc ON nvc.NVD_CVE_ID = c.id
WHERE nvc.id = ? ;"""

cve_details_query_CVEID = """
SELECT c.CVE_ID, c.DESCRIPTION, m.BASE_SCORE, m.BASE_SEVERITY, m.VECTOR_STRING
FROM NVD_CVE c
INNER JOIN NVD_METRIC_CVSS m ON m.NVD_CVE_ID = c.id
WHERE c.CVE_ID = ?;"""


def get_cve_details(cve_id, KB):
    db_path = Path('shawarma.db')
    with sqlite3.connect(str(db_path)) as conn:
        c = conn.cursor()
        c.execute(cve_details_query_CVEID, (cve_id,))
        cve_details_items = c.fetchone()
        if cve_details_items is None:
            return None
        cve_details = {
            "DESCRIPTION": cve_details_items[1],
            "CVSS_SCPRE": cve_details_items[2],
            "AFFECTED_VERSION": KB,
            "SEVERITY": cve_details_items[3],
            "VECTOR_STRING": cve_details_items[4],
        }
    return cve_details


def compare_versions(pkg_version, cve_version, isInclude, isLess):
    if cve_version == None or cve_version == "":
        return True
    try:
        cveV = version.parse(cve_version)
        pkgV = version.parse(pkg_version)
    except:
        return False
    if type(cveV) != type(pkgV):
        return False
    if isInclude:
        if isLess:
            return (pkgV <= cveV)
        else:
            return (pkgV >= cveV)
    else:
        if isLess:
            return (pkgV < cveV)
        else:
            return (pkgV > cveV)


def compare_cpe_strings(cpe1, cpe2):
    cpe1_parts = cpe1.split(":")
    cpe2_parts = cpe2.split(":")

    if len(cpe1_parts) != len(cpe2_parts):
        return False

    for i in range(len(cpe1_parts)):
        if i == 5:  # skip the version part
            continue
        if cpe1_parts[i] != cpe2_parts[i] and cpe2_parts[i] != "*":
            return False

    return True


def search_cpe_CVEs(cpe_string, version, cpe_index):

    cve_details = {}
    db_path = Path("shawarma.db")

    with sqlite3.connect(db_path) as conn:
        c = conn.cursor()
        parts = cpe_string.split(':')
        parts[5] = '*'
        with_edition_no_version = ':'.join(parts)
        parts[5] = version
        cpe_string = ':'.join(parts)  # with edition and version
        parts[9] = '*'
        no_edition_with_version = ':'.join(parts)
        parts[5] = '*'
        no_edition_no_version = ':'.join(parts)
        c.execute("SELECT * FROM NVD_CVE_MATCH WHERE URI = ? OR URI = ? OR URI = ? OR URI = ?",
                  (cpe_string, with_edition_no_version, no_edition_with_version, no_edition_no_version))
        cve_match_items = c.fetchall()
        if len(cve_match_items) == 0:
            return None

        for cve_match_item in cve_match_items:  # cve_match_item == CVE_MATCH ELEMENT
            Vulnerable = cve_match_item[2]
            if Vulnerable == 1:
                cve_match_flag = True
                for i in range(4, 8):
                    cve_match_flag = cve_match_flag and compare_versions(
                        version, cve_match_item[i], i % 2 == 0, i > 5)
                if cve_match_flag or (cpe_string == cve_match_item[3]):

                    # GET ALL CHILDREN WITH THE SAME PARENT OF CVE_MATCH_ITEM
                    c.execute(same_parent_query,
                              (cve_match_item[1], cve_match_item[1]))
                    cve_configurations_same_parent = c.fetchall()

                    # NO CHILDREN WITH THE SAME PARENT
                    if len(cve_configurations_same_parent) == 0:
                        c.execute(cve_details_query_ConfID,
                                  (cve_match_item[1],))
                        cve_details_items = c.fetchone()
                        cve_details[cve_details_items[0]] = {
                            "DESCRIPTION": cve_details_items[1],
                            "CVSS_SCPRE": cve_details_items[2],
                            "AFFECTED_VERSION": version,
                            "SEVERITY": cve_details_items[3],
                            "VECTOR_STRING": cve_details_items[4],
                        }
                        continue

                    cve_configuration_same_parent_flag = True
                    for cve_configuration_same_parent_item in cve_configurations_same_parent:
                        c.execute("SELECT * FROM NVD_CVE_MATCH WHERE NVD_CVE_CONFIGURATION_ID = ?",
                                  (cve_configuration_same_parent_item[0],))
                        same_parent_cve_matches = c.fetchall()
                        for same_parent_cve_match in same_parent_cve_matches:
                            or_flag = False
                            parts = same_parent_cve_match[3].split(':')
                            vendor, product = parts[3], parts[4]
                            vendor_product_part = vendor + ":" + product
                            if cpe_index.get(vendor_product_part):
                                app_version = cpe_index.get(
                                    vendor_product_part).get("Version")
                                app_cpe = cpe_index.get(
                                    vendor_product_part).get("cpe")
                                if compare_cpe_strings(app_cpe, same_parent_cve_match[3]):
                                    or_flag = True
                                    for i in range(4, 8):
                                        or_flag = or_flag and compare_versions(
                                            app_version, same_parent_cve_match[i], i % 2 == 0, i > 5)
                                    if or_flag:
                                        break
                        cve_configuration_same_parent_flag = cve_configuration_same_parent_flag and or_flag
                    if cve_configuration_same_parent_flag:  # ALL CHILDREN WITH THE SAME PARENT ARE PRESENT IN THE APPS.JSON
                        c.execute(cve_details_query_ConfID,
                                  (cve_match_item[1],))
                        cve_details_items = c.fetchone()
                        cve_details[cve_details_items[0]] = {
                            "DESCRIPTION": cve_details_items[1],
                            "CVSS_SCPRE": cve_details_items[2],
                            "AFFECTED_VERSION": version,
                            "SEVERITY": cve_details_items[3],
                            "VECTOR_STRING": cve_details_items[4],
                        }

    return cve_details if cve_details else None


def append_cve_details():
    with open("apps.json", "r") as f:
        applications = json.load(f)

# Create index on cpe field
    cpe_index = {}
    for app in applications:
        if app.get('cpe') and app.get('cpe') != "N/A":
            parts = app.get('cpe').split(':')
            vendor, product = parts[3], parts[4]
            vendor_product_part = vendor + ":" + product
            cpe_index[vendor_product_part] = app
    cve_details = {}
    for app in applications:
        print(custom_prompt("information",
              f"Searching for CVEs for: {app.get('ProgramName')}"))
        cpe_string = app.get("cpe")
        version = app.get("Version")
        edition = app.get("Edition")
        if not cpe_string or cpe_string == "N/A" or not version:
            continue
        app_name = app.get("ProgramName")
        sanitized_cpe = sanitize_cpe_string(cpe_string, version, edition)
        cve_match_item = search_cpe_CVEs(sanitized_cpe, version, cpe_index)
        if cve_match_item:
            cve_details[app_name] = cve_match_item
    with open("cve_details.json", "r") as f:
        cve_details_data = json.load(f)
    cve_details_data.update(cve_details)
    with open("cve_details.json", "w") as f:
        json.dump(cve_details_data, f, indent=4)
