from colorama import Fore, Style, init

def custom_prompt(prompt_type, prompt_text):
    symbol = ''
    color = ''
    if prompt_type == 'errors':
        symbol = 'X'
        color = Fore.RED
    elif prompt_type == 'information':
        symbol = '*'
        color = Fore.BLUE
    elif prompt_type == 'input':
        symbol = '?'
        color = Fore.WHITE
    elif prompt_type == 'warning':
        symbol = '!'
        color = Fore.YELLOW
    else:
        symbol = '*'
        color = Fore.BLUE

    return f'{color}[{symbol}]{Style.RESET_ALL} {Style.BRIGHT}{prompt_text}{Style.RESET_ALL}'

init()
