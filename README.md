<a name="readme-top"></a>





[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/github_username/repo_name">
    <img src="images/profile.jpg" alt="Logo" width="80" height="80">
  </a>

<h3 align="center">ExposurEye</h3>

  <p align="center">
    ExposurEye is a simple tool designed to help users identify security vulnerabilities in their system. The tool works by analyzing software components and comparing them to a database of known Common Vulnerabilities and Exposures (CVEs). The scanner uses the National vulnerability database Feeds to parse and store information about CVEs and to generate cpe strings for installed applications on the system,
    it stores this information in a lightweight sqlite database and then it searches for CVEs for the installed applications, the script also uses [Wazuh](https://wazuh.com) microsoft update feed to find CVEs affecting windows.
    <br />
    <a href="https://github.com/shawarma-man/ExposurEye"><strong>Explore the docs »</strong></a>
    <br />
    <br />
    <a href="https://github.com/shawarma-man/ExposurEye/issues">Report Bug</a>
    ·
    <a href="https://github.com/shawarma-man/ExposurEye/issues">Request Feature</a>
  </p>
</div>



<!-- TABLE OF CONTENTS -->
<details>
  <summary>Table of Contents</summary>
  <ol>
    <li>
      <a href="#about-the-project">About The Project</a>
      <ul>
        <li><a href="#built-with">Built With</a></li>
      </ul>
    </li>
    <li>
      <a href="#getting-started">Getting Started</a>
      <ul>
        <li><a href="#prerequisites">Prerequisites</a></li>
        <li><a href="#installation">Installation</a></li>
      </ul>
    </li>
    <li><a href="#usage">Usage</a></li>
    <li><a href="#license">License</a></li>
    <li><a href="#contact">Contact</a></li>
    <li><a href="#acknowledgments">Acknowledgments</a></li>
  </ol>
</details>



<!-- ABOUT THE PROJECT -->
## About The Project

[![Product Name Screen Shot][product-screenshot]](https://example.com)

Here's a blank template to get started: To avoid retyping too much info. Do a search and replace with your text editor for the following: `github_username`, `repo_name`, `twitter_handle`, `linkedin_username`, `email_client`, `email`, `project_title`, `project_description`

<p align="right">(<a href="#readme-top">back to top</a>)</p>



### Built With

* [![Python][python]][Python-url]
* [![Powershell][powershell]][powershell-url]
* [![Sqlite][sqlite]][sqlite-url]

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- GETTING STARTED -->
## Getting Started

To Use ExposurEye Follow the simple steps explained in the *Installation* Part

### Installation

1. Clone the repo
   ```sh
   git clone https://github.com/github_username/repo_name.git
   ```
2. Install requirements.txt
   ```sh
   pip -r requirements.txt
   ```

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

All you need to do to run start scanning is run main.py:
```sh
python ./main.py
```

<p align="right">(<a href="#readme-top">back to top</a>)</p>


<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Your Name - [@twitter_handle](https://twitter.com/twitter_handle) - ahmedmhj.nu@gmail.com

Project Link: [https://github.com/shawarma-man/ExposurEye](https://github.com/shawarma-man/ExposurEye)

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- ACKNOWLEDGMENTS -->
## Acknowledgments

* []()
* []()
* []()

<p align="right">(<a href="#readme-top">back to top</a>)</p>



<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/shawarma-man/ExposurEye.svg?style=for-the-badge
[contributors-url]: https://github.com/shawarma-man/ExposurEye/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/shawarma-man/ExposurEye.svg?style=for-the-badge
[forks-url]: https://github.com/shawarma-man/ExposurEye/network/members
[stars-shield]: https://img.shields.io/github/stars/shawarma-man/ExposurEye.svg?style=for-the-badge
[stars-url]: https://github.com/shawarma-man/ExposurEye/stargazers
[issues-shield]: https://img.shields.io/github/issues/shawarma-man/ExposurEye.svg?style=for-the-badge
[issues-url]: https://github.com/shawarma-man/ExposurEye/issues
[license-shield]: https://img.shields.io/github/license/shawarma-man/ExposurEye.svg?style=for-the-badge
[license-url]: https://github.com/shawarma-man/ExposurEye/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/ahmed-jalamneh
[product-screenshot]: images/banner.png
[python]: https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white
[Python-url]: https://www.python.org
[powershell]: https://img.shields.io/badge/Powershell-2CA5E0?style=for-the-badge&logo=powershell&logoColor=white
[powershell-url]: https://learn.microsoft.com/en-us/powershell/
[sqlite]: https://img.shields.io/badge/SQLite-07405E?style=for-the-badge&logo=sqlite&logoColor=white
[sqlite-url]: https://sqlite.org
