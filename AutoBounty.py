import os
import subprocess
import argparse
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

# Define the default target domain and output directory
DEFAULT_TARGET_DOMAIN = "magicjackpot.ro"
DEFAULT_OUTPUT_DIR = "/home/kali/Desktop/magicjackpot/"

# Function to run commands using subprocess
def execute_command(command, output_file=None):
    try:
        subprocess.run(
            command, shell=True, check=True, stdout=output_file, stderr=subprocess.PIPE
        )
    except subprocess.CalledProcessError as error:
        print(f"Error running command: {command}")
        print(error.stderr.decode("utf-8"))


# Function to sanitize subdomain names for filenames
def sanitize_filename(filename):
    return filename.replace("/", "_").replace(":", "_")


# Function to execute subdomain enumeration
def run_subdomain_enumeration(target_domain, output_dir):
    print("Running subdomain enumeration...")
    subfinder_cmd = f"subfinder -d {target_domain} -o {output_dir}subdomains.txt"
    amass_cmd = f"amass enum -d {target_domain} -o {output_dir}amass_subdomains.txt"
    sublist3r_cmd = (
        f"sublist3r -d {target_domain} -o {output_dir}sublist3r_subdomains.txt"
    )

    execute_command(subfinder_cmd)
    execute_command(amass_cmd)
    execute_command(sublist3r_cmd)

    print("Subdomain enumeration completed.\n")


# Function to discover live subdomains
def run_live_subdomain_discovery(output_dir):
    print("Running HTTPX for live subdomain discovery...")
    subdomains_file = os.path.join(output_dir, "subdomains.txt")
    amass_subdomains_file = os.path.join(output_dir, "amass_subdomains.txt")
    sublist3r_subdomains_file = os.path.join(output_dir, "sublist3r_subdomains.txt")

    combined_subdomains_file = os.path.join(output_dir, "combined_subdomains.txt")
    execute_command(
        f"cat {subdomains_file} {amass_subdomains_file} {sublist3r_subdomains_file} | sort -u > {combined_subdomains_file}"
    )

    httpx_cmd = (
        f"httpx -l {combined_subdomains_file} -o {output_dir}live_subdomains.txt"
    )
    execute_command(httpx_cmd)

    print("HTTPX execution completed.\n")


# Function to run Nikto on a subdomain
def run_nikto(subdomain, output_dir):
    print(f"Running Nikto for {subdomain}...")
    nikto_output_dir = os.path.join(output_dir, "nikto_results")
    os.makedirs(nikto_output_dir, exist_ok=True)
    nikto_output_file = os.path.join(
        nikto_output_dir, f"{sanitize_filename(subdomain)}_nikto.txt"
    )

    nikto_cmd = f"nikto -h {subdomain} -o {nikto_output_file} -Format txt -Tuning 012345678 -timeout 10"
    execute_command(nikto_cmd)

    print(f"Nikto execution for {subdomain} completed.\n")


# Define Nmap script categories for web application scanning
NMAP_SCRIPT_CATEGORIES = "http-*"

# Function to execute Nmap
def run_nmap(target_domain, output_dir):
    print("Running Nmap for network enumeration and web vulnerability scanning...")
    nmap_output_dir = os.path.join(output_dir, "nmap_results")
    os.makedirs(nmap_output_dir, exist_ok=True)
    nmap_output_file = os.path.join(nmap_output_dir, "nmap_output.txt")

    nmap_cmd = f"nmap -Pn -T4 -F --script {NMAP_SCRIPT_CATEGORIES} -oN {nmap_output_file} {target_domain}"
    execute_command(nmap_cmd)

    print("Nmap execution completed.\n")


# Function to run Aquatone
def run_aquatone(output_dir):
    print("Running Aquatone for subdomain screenshots...")
    live_subdomains_file = os.path.join(output_dir, "live_subdomains.txt")
    aquatone_output_dir = os.path.join(output_dir, "aquatone_output")
    os.makedirs(aquatone_output_dir, exist_ok=True)

    aquatone_cmd = f"cat {live_subdomains_file} | aquatone -out {aquatone_output_dir}"
    execute_command(aquatone_cmd)

    print("Aquatone execution completed.\n")


# Function to run Dirsearch for directory and file discovery
def run_dirsearch(subdomain, output_dir):
    print(f"Running Dirsearch for directory and file discovery on {subdomain}...")
    dirsearch_output_dir = os.path.join(output_dir, "dirsearch_results")
    os.makedirs(dirsearch_output_dir, exist_ok=True)
    wordlist_path = "/path/to/your/wordlist.txt"  # Replace with your wordlist path
    dirsearch_output_file = os.path.join(
        dirsearch_output_dir, f"{sanitize_filename(subdomain)}.txt"
    )

    # Run Dirsearch without specifying 'dirsearch.py'
    dirsearch_cmd = f"dirsearch -u {subdomain} -w {wordlist_path} -o {dirsearch_output_file} -f -m 1 -x 404"
    execute_command(dirsearch_cmd)

    print(f"Dirsearch execution for {subdomain} completed.\n")

# Modify the run_security_scan function to pass the list of live subdomains as follows:
# Run Dirsearch for directory and file discovery
with open(live_subdomains_file, "r") as live_subdomains:
    with ThreadPoolExecutor() as executor:
        for live_subdomain in live_subdomains:
            executor.submit(run_dirsearch, live_subdomain.strip(), output_dir)



# Function to run Nuclei
def run_nuclei(subdomains, output_dir):
    print("Running Nuclei for web vulnerability scanning...")

    nuclei_output_dir = os.path.join(output_dir, "nuclei_results")
    os.makedirs(nuclei_output_dir, exist_ok=True)

    nuclei_output_file = os.path.join(
        nuclei_output_dir, "nuclei_output.txt"
    )  # You can customize the output file name if needed

    # Join the list of subdomains into a single string with spaces
    subdomains_str = " ".join(subdomains)

    nuclei_cmd = f"nuclei -l {subdomains_str} -o {nuclei_output_file}"
    execute_command(nuclei_cmd)

    print(f"Nuclei execution completed.\n")

# Modify the run_security_scan function to pass the list of live subdomains as follows:
# Run Nuclei for web vulnerability scanning
with open(live_subdomains_file, "r") as live_subdomains:
    live_subdomain_list = [line.strip() for line in live_subdomains]
    with ThreadPoolExecutor() as executor:
        executor.submit(run_nuclei, live_subdomain_list, output_dir)

# Function to run Paramspider with sudo
def run_paramspider(subdomain, output_dir):
    print(f"Running Paramspider for parameter discovery on {subdomain}...")
    paramspider_output_dir = os.path.join(output_dir, "paramspider_results")
    os.makedirs(paramspider_output_dir, exist_ok=True)
    paramspider_output_file = os.path.join(
        paramspider_output_dir, f"{sanitize_filename(subdomain)}.txt"
    )

    # Run Paramspider with sudo
    paramspider_cmd = f" paramspider -d {subdomain} -o {paramspider_output_file}"
    execute_command(paramspider_cmd)

    print(f"Paramspider execution for {subdomain} completed.\n")

# Modify the run_security_scan function to pass the list of live subdomains as follows:
# Run Paramspider for parameter discovery
with open(live_subdomains_file, "r") as live_subdomains:
    with ThreadPoolExecutor() as executor:
        for live_subdomain in live_subdomains:
            executor.submit(run_paramspider, live_subdomain.strip(), output_dir)



# Function to run wafw00f against a list of subdomains
def run_wafw00f(live_subdomains, output_dir):
    wafw00f_output_dir = os.path.join(output_dir, "wafw00f_results")
    os.makedirs(wafw00f_output_dir, exist_ok=True)
    wafw00f_output_file = os.path.join(wafw00f_output_dir, "wafw00f_output.txt")

    print("Running WAF detection using wafw00f...")
    
    # Create a comma-separated string of live subdomains
    live_subdomains_str = ",".join(live_subdomains)

    wafw00f_cmd = f"wafw00f -i {live_subdomains_str} -o {wafw00f_output_file}"
    execute_command(wafw00f_cmd)
    print("WAF detection using wafw00f completed.\n")

# Modify the run_security_scan function to pass the list of live subdomains as follows:
# Detect WAFs
with open(live_subdomains_file, "r") as live_subdomains:
    live_subdomain_list = [line.strip() for line in live_subdomains]
    with ThreadPoolExecutor() as executor:
        executor.submit(run_wafw00f, live_subdomain_list, output_dir)




# Function to generate the HTML report
def generate_html_report(output_dir):
    print("Generating HTML report...")
    html_report = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Security Scan Report</title>
    </head>
    <body>
        <h1>Security Scan Report</h1>
    """

    # Include subdomain enumeration results
    html_report += "<h2>Subdomain Enumeration Results</h2>"
    subdomains_file = os.path.join(output_dir, "subdomains.txt")
    with open(subdomains_file, "r") as subdomains:
        html_report += "<ul>"
        for subdomain in subdomains:
            html_report += f"<li>{subdomain.strip()}</li>"
        html_report += "</ul>"

    # Include live subdomain discovery results
    html_report += "<h2>Live Subdomain Discovery Results</h2>"
    live_subdomains_file = os.path.join(output_dir, "live_subdomains.txt")
    with open(live_subdomains_file, "r") as live_subdomains:
        html_report += "<ul>"
        for live_subdomain in live_subdomains:
            html_report += f"<li>{live_subdomain.strip()}</li>"
        html_report += "</ul>"

    # Include Nikto scan results
    html_report += "<h2>Nikto Scan Results</h2>"
    nikto_results_dir = os.path.join(output_dir, "nikto_results")
    for root, _, files in os.walk(nikto_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as nikto_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += nikto_output.read()
                html_report += "</pre>"

    # Include Nmap scan results
    html_report += "<h2>Nmap Scan Results</h2>"
    nmap_results_dir = os.path.join(output_dir, "nmap_results")
    for root, _, files in os.walk(nmap_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as nmap_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += nmap_output.read()
                html_report += "</pre>"

    # Include Aquatone results
    html_report += "<h2>Aquatone Results</h2>"
    aquatone_results_dir = os.path.join(output_dir, "aquatone_output")
    for root, _, files in os.walk(aquatone_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as aquatone_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += aquatone_output.read()
                html_report += "</pre>"

    # Include Dirsearch results
    html_report += "<h2>Dirsearch Results</h2>"
    dirsearch_results_dir = os.path.join(output_dir, "dirsearch_results")
    for root, _, files in os.walk(dirsearch_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as dirsearch_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += dirsearch_output.read()
                html_report += "</pre>"

    # Include Nuclei results
    html_report += "<h2>Nuclei Results</h2>"
    nuclei_results_dir = os.path.join(output_dir, "nuclei_results")
    for root, _, files in os.walk(nuclei_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as nuclei_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += nuclei_output.read()
                html_report += "</pre>"

    # Include Paramspider results
    html_report += "<h2>Paramspider Results</h2>"
    paramspider_results_dir = os.path.join(output_dir, "paramspider_results")
    for root, _, files in os.walk(paramspider_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as paramspider_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += paramspider_output.read()
                html_report += "</pre>"

    # Include WAF detection results
    html_report += "<h2>WAF Detection Results</h2>"
    wafw00f_results_dir = os.path.join(output_dir, "wafw00f_results")
    for root, _, files in os.walk(wafw00f_results_dir):
        for file in files:
            with open(os.path.join(root, file), "r") as wafw00f_output:
                html_report += f"<h3>{file}</h3>"
                html_report += "<pre>"
                html_report += wafw00f_output.read()
                html_report += "</pre>"

    # HTML report footer
    html_report += """
    </body>
    </html>
    """

    # Save the HTML report to a file
    report_file = os.path.join(output_dir, "security_scan_report.html")
    with open(report_file, "w") as report:
        report.write(html_report)

    print(f"HTML report generated: {report_file}\n")


# Function to execute all scan steps
def run_security_scan(target_domain, output_dir):
    # Run subdomain enumeration
    run_subdomain_enumeration(target_domain, output_dir)

    # Run live subdomain discovery
    run_live_subdomain_discovery(output_dir)

    # Run Nikto on live subdomains
    live_subdomains_file = os.path.join(output_dir, "live_subdomains.txt")
    with open(live_subdomains_file, "r") as live_subdomains:
        with ThreadPoolExecutor() as executor:
            for live_subdomain in live_subdomains:
                executor.submit(run_nikto, live_subdomain.strip(), output_dir)

    # Run Nmap for network enumeration and web vulnerability scanning
    run_nmap(target_domain, output_dir)

    # Run Aquatone for subdomain screenshots
    run_aquatone(output_dir)

    # Run Dirsearch for directory and file discovery
    with open(live_subdomains_file, "r") as live_subdomains:
        with ThreadPoolExecutor() as executor:
            for live_subdomain in live_subdomains:
                executor.submit(run_dirsearch, live_subdomain.strip(), output_dir)

    # Run Nuclei for web vulnerability scanning
    with open(live_subdomains_file, "r") as live_subdomains:
        with ThreadPoolExecutor() as executor:
            for live_subdomain in live_subdomains:
                executor.submit(run_nuclei, live_subdomain.strip(), output_dir)

    # Run Paramspider for parameter discovery
    with open(live_subdomains_file, "r") as live_subdomains:
        with ThreadPoolExecutor() as executor:
            for live_subdomain in live_subdomains:
                executor.submit(run_paramspider, live_subdomain.strip(), output_dir)

    # Detect WAFs
    with open(live_subdomains_file, "r") as live_subdomains:
        with ThreadPoolExecutor() as executor:
            for live_subdomain in live_subdomains:
                executor.submit(run_waf_detection, live_subdomain.strip(), output_dir)

    # Generate the HTML report
    generate_html_report(output_dir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Security Scanning Script")
    parser.add_argument(
        "target_domain", type=str, help="The target domain to scan (e.g., example.com)"
    )
    parser.add_argument(
        "--output_dir",
        type=str,
        default=DEFAULT_OUTPUT_DIR,
        help="The directory to store scan results",
    )

    args = parser.parse_args()
    target_domain = args.target_domain
    output_dir = args.output_dir

    # Create the output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)

    # Get the current date and time for the report
    current_datetime = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print(f"Security scan started for {target_domain} at {current_datetime}\n")

    # Create a ThreadPoolExecutor with a specified number of worker threads
    with ThreadPoolExecutor(max_workers=10) as executor:
        # Execute the security scan using the executor
        run_security_scan(target_domain, output_dir)

    print(f"Security scan completed for {target_domain} at {current_datetime}\n")
