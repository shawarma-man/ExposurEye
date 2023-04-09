import difflib
from pathlib import Path
import sqlite3
from fuzzywuzzy import fuzz
def sanitize_cpe_string(cpe_string):
    if(cpe_string == None):
        return None
    cpe_parts = cpe_string.split(':')
    if len(cpe_parts) >= 7:
        cpe_parts[5:] = ['*'] * (len(cpe_parts) - 5)
    return ':'.join(cpe_parts)


def get_best_cpe(app_name, vendor, version):
    best_cpe = None
    best_score = 0
    if app_name.lower() == vendor.lower() and "_" in app_name:
        vendor,app_name = app_name.split("_")
    db_path = Path('shawarma.db')
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    query = """
    SELECT *
    FROM NVD_CPE
    WHERE PRODUCT LIKE ? OR VENDOR LIKE ?
    """
    c.execute(query, ('%'+app_name+'%', '%'+vendor+'%'))
    rows = c.fetchall()
    if len(rows) == 0:
        return best_cpe,best_score
    rows = sorted(rows, key=lambda x: (fuzz.ratio(x[2], vendor) + fuzz.ratio(x[3], app_name)) / 2, reverse=True)
    for row in rows:
        if((best_score/2) >= 0.95) and '-' != best_cpe.split(":")[5]:
            break
        cpe_list = ["cpe:2.3:", row[1], ":", row[2], ":", row[3], ":", row[4], ":", row[5],
                     ":", row[6], ":", row[7], ":", row[8], ":", row[9], ":", row[10], ":", row[11]]
        cpe_str = "".join(cpe_list)
        cpe_vendor = row[2]
        cpe_product = row[3]
        score = 0
        # if vendor.lower() in cpe_vendor.lower():
        #     score += 1
        # if app_name.lower() in cpe_str.lower():
        #     score += 1
        
        # Check for similarity between the cpe string and the app name and vendor
        sequence_matcher = difflib.SequenceMatcher(a=app_name.lower(), b=cpe_product.lower())
        similarity_score = sequence_matcher.ratio()
        score += similarity_score

        sequence_matcher = difflib.SequenceMatcher(a=vendor.lower(), b=cpe_vendor.lower())
        similarity_score = sequence_matcher.ratio()

        sequence_matcher = difflib.SequenceMatcher(a=app_name.lower(), b=cpe_vendor.lower())
        if sequence_matcher.ratio() == 1.0:
            similarity_score = sequence_matcher.ratio()
        
        sequence_matcher = difflib.SequenceMatcher(a=app_name.lower(), b=(cpe_vendor.lower()+" "+cpe_product.lower()))
        if sequence_matcher.ratio() > similarity_score:
            similarity_score = sequence_matcher.ratio()
        score += similarity_score
        
        if ((score > best_score) or ((score == best_score) and '-' != cpe_str.split(":")[5] and '-' == best_cpe.split(":")[5])):
            best_cpe = cpe_str
            best_score = score
    return sanitize_cpe_string(best_cpe),(best_score/2)                      