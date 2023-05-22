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
        choice = input(custom_prompt(
            'information', 'Database already exists, would you like to update it? (y/n) Default:y\n')).lower()
        if choice not in ['n', 'no']:
            db_path.unlink()
            create_msu_db()
    else:
        create_msu_db()
    getWindowsCVE()
    getAppsCVE()
    file_paths = ['msu.json', 'installed_hotfixes.txt', 'cpe_dictionary.xml']

    for file_path in file_paths:
        file = Path(file_path)
        if file.exists():
            file.unlink()


if __name__ == '__main__':
    main()
