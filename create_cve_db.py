import datetime
import gzip
import json
from pathlib import Path
import sqlite3
import requests
from tqdm import tqdm
from custom_prompts import custom_prompt
import xml.etree.ElementTree as ET
def conf_nodes_recursion(node, parent_id,cve_id, db_conn):
    
    operator = node.get('operator')
    c = db_conn.cursor()
    cpe_match_list = []

    for cpe_match in node.get('cpe_match', []):
        
        cpe_str = cpe_match.get('cpe23Uri').replace('\\', '')
        cpe_parts = cpe_str.split(':')
        
        vulnerable = 1 if cpe_match.get('vulnerable') else 0
        version_start_inc = cpe_match.get('versionStartIncluding', None)
        version_start_exc = cpe_match.get('versionStartExcluding', None)
        version_end_inc = cpe_match.get('versionEndIncluding', None)
        version_end_exc = cpe_match.get('versionEndExcluding', None)
        cpe_match_list.append((vulnerable, cpe_str, version_start_inc, version_start_exc, version_end_inc, version_end_exc))
    c.execute('''INSERT INTO NVD_CVE_CONFIGURATION (NVD_CVE_ID, PARENT, OPERATOR) VALUES (?, ?, ?)''', (cve_id, parent_id, operator))
    parent_id = c.lastrowid
    c.executemany('''INSERT INTO NVD_CVE_MATCH (NVD_CVE_CONFIGURATION_ID, VULNERABLE, URI,
                    VERSION_START_INCLUDING, VERSION_START_EXCLUDING, VERSION_END_INCLUDING, VERSION_END_EXCLUDING)
                    VALUES (?, ?, ?, ?, ?, ?, ?)''', [(parent_id, *cpe_match_data) for cpe_match_data in cpe_match_list])
    for child in node.get('children', []):
        conf_nodes_recursion(child, parent_id,cve_id, db_conn)



def create_msu_db():
    print(custom_prompt('information','Downloading MSU and CPE data...'))
    msu_path = Path('msu.json')
    cpe_path = Path('cpe_dictionary.xml')

    url = 'https://nvd.nist.gov/feeds/xml/cpe/dictionary/official-cpe-dictionary_v2.3.xml.gz'
    r = requests.get(url)
    with open(cpe_path, 'wb') as f:
        f.write(gzip.decompress(r.content))
    
    url = 'https://feed.wazuh.com/vulnerability-detector/windows/msu-updates.json.gz'
    r = requests.get(url)
    
    with open(msu_path, 'wb') as f:
        f.write(gzip.decompress(r.content))
    
    

    # Connect to database and create table
    db_path = Path('shawarma.db')
    with sqlite3.connect(str(db_path)) as conn:
        print(custom_prompt('information','Creating Hotfixes dependecies table...'))
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS msu_supersedence
             (Patch text, Super text, PRIMARY KEY(Patch, Super))''')
        

        # Read in MSU data

        # Parse dependencies and insert into table
        # Read in MSU data
        with open(msu_path) as f:
            msu_data = json.load(f)

        # Parse dependencies and insert into table
        for patch, supers_list in msu_data['dependencies'].items():
            
            if patch.startswith("KB") and patch[2:].isdigit():
                
                supers_list.append(patch)
                for supers in supers_list:
                    try:
                        c.execute("INSERT INTO msu_supersedence VALUES (?, ?)", (patch[2:], supers[2:]))
                    except sqlite3.IntegrityError:
                        pass
        
        c.execute('''CREATE TABLE IF NOT EXISTS msu
             (CVEID text NOT NULL, PRODUCT text NOT NULL, PATCH text NOT NULL, TITLE text,URL text,restart_required text,subtype text, PRIMARY KEY(CVEID, PRODUCT))''')
        print(custom_prompt('information','Creating msu CVEs table...'))
        for cve in tqdm(msu_data['vulnerabilities'], desc='Checking vulnerabilities'):
            for product_info in msu_data['vulnerabilities'][cve]:
                product = product_info['product']
                patch = product_info['patch']
                title = product_info['title']
                url = product_info['url']
                restart_required = product_info['restart_required']
                subtype = product_info['subtype']
                try:
                    c.execute("INSERT INTO msu VALUES (?, ?, ?, ?, ?, ?, ?)", (cve, product, patch[2:], title, url, restart_required, subtype))
                except sqlite3.IntegrityError:
                    
                    pass
        del msu_data
        print(custom_prompt('information','Creating CPE table...'))
        c.execute('''CREATE TABLE NVD_CPE (
                 ID INTEGER PRIMARY KEY AUTOINCREMENT,
                 PART TEXT NOT NULL,
                 VENDOR TEXT,
                 PRODUCT TEXT,
                 VERSION TEXT,
                 UPDATED TEXT,
                 EDITION TEXT,
                 LANGUAGE TEXT,
                 SW_EDITION TEXT,
                 TARGET_SW TEXT,
                 TARGET_HW TEXT,
                 OTHER TEXT,
                 UNIQUE(PART, VENDOR, PRODUCT, VERSION, UPDATED, EDITION, LANGUAGE, SW_EDITION, TARGET_SW, TARGET_HW, OTHER)
              )''')

        # Add indexes to the NVD_CPE table
        c.execute('CREATE INDEX IN_NVD_CPE_ID ON NVD_CPE (ID)')
        c.execute('CREATE INDEX IN_NVD_CPE_PART ON NVD_CPE (PART)')
        c.execute('CREATE INDEX IN_NVD_CPE_VENDOR ON NVD_CPE (VENDOR)')
        c.execute('CREATE INDEX IN_NVD_CPE_PRODUCT ON NVD_CPE (PRODUCT)')
        c.execute('CREATE INDEX IN_NVD_CPE_VERSION ON NVD_CPE (VERSION)')
        c.execute('CREATE INDEX IN_NVD_CPE_UPDATED ON NVD_CPE (UPDATED)')
        c.execute('CREATE INDEX IN_NVD_CPE_EDITION ON NVD_CPE (EDITION)')
        c.execute('CREATE INDEX IN_NVD_CPE_LANGUAGE ON NVD_CPE (LANGUAGE)')
        c.execute('CREATE INDEX IN_NVD_CPE_SW_EDITION ON NVD_CPE (SW_EDITION)')
        c.execute('CREATE INDEX IN_NVD_CPE_TARGET_SW ON NVD_CPE (TARGET_SW)')
        c.execute('CREATE INDEX IN_NVD_CPE_TARGET_HW ON NVD_CPE (TARGET_HW)')
        c.execute('CREATE INDEX IN_NVD_CPE_OTHER ON NVD_CPE (OTHER)')

        # Parse the CPE dictionary and insert into the NVD_CPE table
        print(custom_prompt('information','Creating NVD_CPE table...'))
        for event, elem in ET.iterparse('cpe_dictionary.xml', events=('start', 'end')):
            if event == 'end' and elem.tag == '{http://cpe.mitre.org/dictionary/2.0}cpe-item':
                cpe23_item = elem.find('{http://scap.nist.gov/schema/cpe-extension/2.3}cpe23-item')
                if cpe23_item is None:
                    continue
                cpe_str = cpe23_item.attrib['name'].replace('\\', '')
                cpe_parts = cpe_str.split(':')
                data = (cpe_parts[2], cpe_parts[3], cpe_parts[4], cpe_parts[5] if len(cpe_parts) > 5 else '',
                        cpe_parts[6] if len(cpe_parts) > 6 else '', cpe_parts[7] if len(cpe_parts) > 7 else '',
                        cpe_parts[8] if len(cpe_parts) > 8 else '', cpe_parts[9] if len(cpe_parts) > 9 else '',
                        cpe_parts[10] if len(cpe_parts) > 10 else '', cpe_parts[11] if len(cpe_parts) > 11 else '',
                        cpe_parts[12] if len(cpe_parts) > 12 else '')
                c.execute('''INSERT OR IGNORE INTO NVD_CPE
                                    (PART, VENDOR, PRODUCT, VERSION, UPDATED, EDITION, LANGUAGE, SW_EDITION, TARGET_SW, TARGET_HW, OTHER)
                                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)''', data)
                elem.clear()
        print(custom_prompt('information','Creating NVD_CVE tables...'))
        c.execute('''CREATE TABLE NVD_CVE (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                NVD_METADATA_YEAR INTEGER,
                CVE_ID TEXT NOT NULL,
                CWE_ID TEXT,
                ASSIGNER TEXT,
                DESCRIPTION TEXT,
                VERSION TEXT,
                PUBLISHED INTEGER,
                LAST_MODIFIED INTEGER
            )''')

        c.execute('''CREATE INDEX IN_NVD_CVE_ID ON NVD_CVE (ID)''')
        c.execute('''CREATE INDEX IN_NVD_CVE_YEAR ON NVD_CVE (NVD_METADATA_YEAR)''')

        conn.execute('''CREATE TABLE NVD_CVE_CONFIGURATION (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                NVD_CVE_ID INTEGER,
                PARENT INTEGER DEFAULT 0,
                OPERATOR TEXT)''')

        # Create the indexes
        conn.execute('CREATE INDEX IN_CONF_ID ON NVD_CVE_CONFIGURATION (ID)')
        conn.execute('CREATE INDEX IN_CONF_PARENT ON NVD_CVE_CONFIGURATION (PARENT)')
        conn.execute('CREATE INDEX IN_CONF_OPERATOR ON NVD_CVE_CONFIGURATION (OPERATOR)')
        conn.execute('CREATE INDEX IN_CONF_CVE_ID ON NVD_CVE_CONFIGURATION (NVD_CVE_ID)')

        conn.execute('''
            CREATE TABLE NVD_CVE_MATCH (
                ID INTEGER PRIMARY KEY AUTOINCREMENT,
                NVD_CVE_CONFIGURATION_ID INTEGER,
                VULNERABLE INTEGER,
                URI TEXT,
                VERSION_START_INCLUDING TEXT,
                VERSION_START_EXCLUDING TEXT,
                VERSION_END_INCLUDING TEXT,
                VERSION_END_EXCLUDING TEXT
                    );
                    ''')
        

        # conn.execute('''
        #     CREATE TABLE NVD_CVE_MATCH (
        #         ID INTEGER PRIMARY KEY AUTOINCREMENT,
        #         NVD_CVE_CONFIGURATION_ID INTEGER,
        #         ID_CPE INTEGER,
        #         VULNERABLE INTEGER,
        #         URI TEXT,
        #         VERSION_START_INCLUDING TEXT,
        #         VERSION_START_EXCLUDING TEXT,
        #         VERSION_END_INCLUDING TEXT,
        #         VERSION_END_EXCLUDING TEXT
        #             );
        #             ''')

        conn.execute('CREATE INDEX IN_MATCH_ID ON NVD_CVE_MATCH (ID);')
        conn.execute('CREATE INDEX IN_MATCH_NVDCVE_ID ON NVD_CVE_MATCH (NVD_CVE_CONFIGURATION_ID);')
        # conn.execute('CREATE INDEX IN_MATCH_ID_CPE ON NVD_CVE_MATCH (ID_CPE);')
        conn.execute('CREATE INDEX IN_MATCH_VULNERABLE ON NVD_CVE_MATCH (VULNERABLE);')

        c.execute('''CREATE TABLE NVD_METRIC_CVSS (
                 ID INTEGER PRIMARY KEY AUTOINCREMENT,
                 NVD_CVE_ID INTEGER,
                 VERSION TEXT,
                 VECTOR_STRING TEXT,
                 BASE_SCORE REAL,
                 BASE_SEVERITY TEXT,
                 EXPLOITABILITY_SCORE REAL,
                 IMPACT_SCORE REAL
              )''')

        c.execute('''CREATE INDEX IN_CVSS_NVDCVE_ID ON NVD_METRIC_CVSS (NVD_CVE_ID)''')


        print(custom_prompt('information','Creating NVD_CVE table...'))
        year = input(custom_prompt('information','Enter the start year for the CVE feed: '))
        while not year.isdigit():
            year = input(custom_prompt('information','Enter the start year for the CVE feed: '))
        year = int(year)
        print(custom_prompt('warning','generating CVE feed for years {} to {}, Warning it may take some time to finish...'.format(year,datetime.datetime.now().year)))


        while year <= datetime.datetime.now().year:
            print(custom_prompt('information','Downloading CVE feed for year {}...'.format(year)))
            url = f"https://nvd.nist.gov/feeds/json/cve/1.1/nvdcve-1.1-{year}.json.gz"
            headers = {'User-Agent': 'Mozilla/5.0'}
            response = requests.get(url, headers=headers, stream=True)
            if response.status_code != 200:
                raise ValueError(custom_prompt('error','Failed to download CVE feed for year {}.'.format(year)))
            try:
                # decompress the response content using gzip
                cve_feed = json.loads(gzip.decompress(response.content).decode('utf-8'))
            except json.JSONDecodeError:
                raise ValueError(custom_prompt('error','Failed to decompress CVE feed for year {}.'.format(year)))
            
            for cve in tqdm(cve_feed['CVE_Items'], desc='Checking vulnerabilities'):
                cve_id = cve['cve']['CVE_data_meta']['ID']
                cwe_id = cve['cve']['problemtype']['problemtype_data'][0]['description'][0]['value'] if ('problemtype' in cve['cve'] and len(cve['cve']['problemtype']['problemtype_data'][0]['description']) > 0) else ''
                assigner = cve['cve']['CVE_data_meta']['ASSIGNER'] if 'ASSIGNER' in cve['cve']['CVE_data_meta'] else ''
                description = cve['cve']['description']['description_data'][0]['value'] if len(cve['cve']['description']['description_data']) > 0 else ''
                version = cve['configurations']['CVE_data_version'] if 'configurations' in cve else ''
                published = cve['publishedDate'] if 'publishedDate' in cve else ''
                last_modified = cve['lastModifiedDate'] if 'lastModifiedDate' in cve else ''
                Cvss = cve['impact']['baseMetricV3']['cvssV3'] if 'baseMetricV3' in cve['impact'] else cve['impact']['baseMetricV2']['cvssV2'] if 'baseMetricV2' in cve['impact'] else ''
                base_metrics = cve['impact']['baseMetricV3'] if 'baseMetricV3' in cve['impact'] else cve['impact']['baseMetricV2'] if 'baseMetricV2' in cve['impact'] else ''
                if Cvss:
                    cvss_version = Cvss['version']
                    vector_string = Cvss['vectorString']
                    base_score = Cvss['baseScore']
                    base_severity = Cvss['baseSeverity']
                    exploitability_score = base_metrics['exploitabilityScore'] if 'exploitabilityScore' in base_metrics else ''
                    impact_score = base_metrics['impactScore'] if 'impactScore' in base_metrics else ''
                c.execute('''INSERT OR IGNORE INTO NVD_CVE
                                (NVD_METADATA_YEAR, CVE_ID, CWE_ID, ASSIGNER, DESCRIPTION, VERSION, PUBLISHED, LAST_MODIFIED)
                                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                            ''', (year, cve_id, cwe_id, assigner, description, version, published, last_modified))
                lastid = c.lastrowid
                c.execute('''INSERT OR IGNORE INTO NVD_METRIC_CVSS (NVD_CVE_ID, VERSION, VECTOR_STRING, BASE_SCORE, BASE_SEVERITY, EXPLOITABILITY_SCORE, IMPACT_SCORE)
                                VALUES (?, ?, ?, ?, ?, ?, ?)
                            ''', (lastid, cvss_version, vector_string, base_score,base_severity, exploitability_score, impact_score))
                for node in cve['configurations']['nodes']:
                    conf_nodes_recursion(node, 0, lastid, conn)
            del cve_feed   
            year += 1

        # Add indexes to the NVD_CVE table