import os
from colored import fg, attr
import pyfiglet

def display_banner():
    os.system('CLS')  # Clear the terminal screen
    ascii_banner = pyfiglet.figlet_format("ExposurEye", font='epic', width=os.get_terminal_size().columns, justify='center')
    gradient_banner = gradient_text(ascii_banner, ['red', 'white'])


    horizontal_line = "=" * os.get_terminal_size().columns

    # calculate terminal center position
    center_position = (os.get_terminal_size().columns - len(gradient_banner)) // 2


    print(horizontal_line)

    # print the banner with center alignment
    print(" " * center_position + gradient_banner)




    vulnerability_scanner_text = "Vulnerability scanner"
    vulnerability_scanner_center_position = (os.get_terminal_size().columns - len(vulnerability_scanner_text)) // 2
    print(" " * vulnerability_scanner_center_position + vulnerability_scanner_text)
    project_info_text = "Project By: @shawarma-man  |  GitHub: https://github.com/shawarma-man"
    project_info_center_position = (os.get_terminal_size().columns - len(project_info_text)) // 2
    print(" " * project_info_center_position + project_info_text)

    print(horizontal_line)
def gradient_text(text, colors):
    color_range = len(colors) - 1
    gradient_chars = []

    for char in text:
        gradient_chars.append(fg(colors[color_range]) + char + attr('reset'))

        if color_range == 0:
            color_range = len(colors) - 1
        else:
            color_range -= 1

    return ''.join(gradient_chars)