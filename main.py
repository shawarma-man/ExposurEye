from pathlib import Path
from create_cve_db import create_msu_db
from custom_prompts import custom_prompt
from getWindowsCVE import getWindowsCVE
from banner import display_banner
from getAppsCVE import getAppsCVE

def main():
    display_banner()
    db_path = Path('shawarma.db')
    if db_path.exists():
        choice = input(custom_prompt('information','Database already exists, would you like to update it? (y/n) Default:y\n')).lower()
        if choice not in ['n', 'no']:
            db_path.unlink()
            create_msu_db()
    else:
        create_msu_db()
    getWindowsCVE()
    getAppsCVE()
    Path('msu.json').unlink()
    Path('installed_hotfixes.txt').unlink()
    Path('cpe_dictionary.xml').unlink()

if __name__ == '__main__':
    main()
