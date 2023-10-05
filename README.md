# AutoBounty

**A Versatile Framework for Custom Automation and Vulnerability Discovery**

AutoBounty is a Python script that automates various security scanning tasks for a target domain. It harnesses the power of popular security tools such as Subfinder, Amass, Nikto, Nmap, Aquatone, Dirsearch, Nuclei, Paramspider, and Wafw00f to perform subdomain enumeration, live subdomain discovery, web vulnerability scanning, and more. The script efficiently utilizes a ThreadPoolExecutor to parallelize tasks, enhancing the scanning process.

## Current Process

- Subdomain enumeration using Subfinder, Amass, and Sublist3r
- Discovery of live subdomains using HTTPX
- Nikto scans on live subdomains in parallel
- Nmap scans for network enumeration and web vulnerability scanning
- Aquatone for subdomain screenshots
- Dirsearch for directory and file discovery
- Nuclei for web vulnerability scanning
- Paramspider for parameter discovery
- Detection of Web Application Firewalls (WAFs) using Wafw00f
- Generation of an HTML report summarizing the scan results

## Prerequisites

Before using this script, ensure that you have the following prerequisites installed on your system:

- Python 3.x
- The required Python packages (you can install them using `pip`):
  - `subprocess`
  - `argparse`
  - `concurrent.futures.ThreadPoolExecutor`
- Security tools:
  - Subfinder
  - Amass
  - Sublist3r
  - Nikto
  - Nmap
  - Aquatone
  - Dirsearch
  - Nuclei
  - Paramspider
  - Wafw00f

Make sure the above tools are correctly installed and available in your system's PATH.

## Usage

python AutoBounty.py example.com --output_dir /path/to/output_directory


  <target_domain>: The target domain to scan (e.g. example.com).
  --output_dir <output_directory> (optional): The directory to store scan results. If not specified, the default output directory will be used.

Output

The script stores scan results, including subdomains, live subdomains, scan reports, and screenshots, in the specified output_directory.


This script leverages popular security tools and libraries. Special thanks to the developers of these tools for their contributions to the security community.

See the LICENSE file for details.
Disclaimer

Note: This security scanning script is provided for educational and ethical testing purposes only. By using this script, you acknowledge that you are responsible for complying with all applicable laws and regulations, and you agree that the author is not liable for any misuse or damage caused by this script. Use this tool responsibly and with proper authorization. Always obtain proper permissions and ensure that you have the necessary rights and consents before scanning any target.

The author takes zero responsibility for any misuse of this tool.

## Acknowledgments

Id like to give a shoutout to the following folks and projects for making AutoBounty possible:

- The awesome developers of the security tools we've integrated into AutoBounty, like Subfinder, Amass, Sublist3r, Nikto, Nmap, Aquatone, Dirsearch, Nuclei, Paramspider, and Wafw00f. Your tools rock!

- The fantastic open-source community for their invaluable feedback, bug reports, feature ideas, and overall support. You all help make AutoBounty better with each update.

- The Python team for creating Python and the creators of libraries like concurrent.futures and argparse that make our lives easier.

- Cybersecurity pros, researchers, and enthusiasts who inspire us every day with their knowledge and passion for security.

Big thanks to everyone who's contributed in any way to AutoBounty's development. You're awesome!

