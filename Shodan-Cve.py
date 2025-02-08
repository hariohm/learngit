import requests
import time
import socket
import sys
from io import StringIO
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

class DualStream:
    """A class to redirect output to both the console and a file."""
    def __init__(self, console_stream, file_stream):
        self.console_stream = console_stream
        self.file_stream = file_stream
        self.buffer = StringIO()  # Initialize the buffer here

    def write(self, message):
        self.console_stream.write(message)  # Output to the console
        self.buffer.write(message)  # Write to the buffer for later file output

    def flush(self):
        self.console_stream.flush()
        self.file_stream.flush()

    def get_output(self):
        return self.buffer.getvalue()  # Get the content of the buffer

def help_menu():
    """Displays the help menu with instructions on how to use the tool."""
    help_text = """
    This tool allows you to gather Shodan data for an IP address and fetch CVE details for associated vulnerabilities.

    Commands:

    1. Enter a Domain Name:
        - The tool will resolve the domain name to an IP address.

    2. Shodan Information:
        - Once the IP is resolved, the tool will fetch Shodan data (IP, hostnames, ports, etc.).

    3. CVE Information:
        - The tool will also display vulnerability information for the associated CVEs (Common Vulnerabilities and Exposures).

    4. Exit:
        - Type 'exit' to quit the tool.

    Additional Information:
    - For CVE information, the top 6 CVEs will be fetched automatically.
    - The tool will display CVE summaries, CVSS scores, and the CVSS version.
    - Vulnerabilities are displayed in a user-friendly format.

    Example:
        Enter the domain name (e.g., example.com), and the tool will show you details such as:
        - IP address
        - Hostnames
        - Open ports
        - CVEs associated with the IP address

    Enjoy using the tool!
    """
    print(Fore.CYAN + "=" * 50)
    print(Fore.YELLOW + "Help Menu:")
    print(Fore.GREEN + "=" * 50)
    print(Fore.WHITE + help_text)
    print(Fore.GREEN + "=" * 50)

def get_ip_from_domain(domain):
    try:
        # Get the IP address from the domain name using DNS lookup
        ip = socket.gethostbyname(domain)
        print(Fore.YELLOW + f"Resolved IP: {ip}")
        return ip
    except socket.gaierror:
        print(Fore.RED + f"Error: Unable to resolve domain '{domain}' to an IP address.")
        return None

def get_shodan_info(ip_address):
    url = f"https://internetdb.shodan.io/{ip_address}"
    response = requests.get(url)

    if response.status_code == 200:
        data = response.json()
        print(Fore.CYAN + "=" * 50)
        print(Fore.YELLOW + "Shodan Info for IP Address: " + Fore.GREEN + ip_address)
        print(Fore.CYAN + "=" * 50)
        print(f"{'IP Address:':<20} {data.get('ip', 'Not Available')}")
        print(f"{'Hostnames:':<20} {', '.join(data.get('hostnames', ['Not Available']))}")
        print(f"{'Ports:':<20} {', '.join(map(str, data.get('ports', ['Not Available'])))}")
        print(f"{'Tags:':<20} {', '.join(data.get('tags', ['Not Available']))}\n")

        # Get the list of vulnerabilities and count them
        vulnerabilities = data.get('vulns', [])
        vuln_count = len(vulnerabilities)

        print(Fore.YELLOW + f"Vulnerabilities Detected ({vuln_count}):")
        if vuln_count > 0:
            for cve in vulnerabilities:
                print(Fore.RED + f"- {cve}")
        else:
            print(Fore.GREEN + "No vulnerabilities found.")

        print(f"{'Associated CPEs:':<20} {', '.join(data.get('cpes', ['Not Available']))}")
        print(Fore.CYAN + "=" * 50)

        # Fetch CVE details for each CVE ID
        for cve in vulnerabilities[:6]:  # Limiting to top 6 CVEs
            fetch_cve_details(cve)
    else:
        print(Fore.RED + f"Failed to retrieve Shodan data for IP: {ip_address}")

def fetch_cve_details(cve_id):
    cve_url = f"https://cvedb.shodan.io/cve/{cve_id}"
    response = requests.get(cve_url)

    if response.status_code == 200:
        cve_data = response.json()
        print(Fore.CYAN + "=" * 50)
        print(Fore.YELLOW + f"Fetching details for CVE: {cve_id}...")
        print(Fore.CYAN + "=" * 50)
        print(f"CVE ID: {cve_data.get('cve_id', 'Not Available')}")
        print(f"Summary: {indent_text(cve_data.get('summary', 'Not Available'))}")
        print(f"CVSS Score: {cve_data.get('cvss', 'Not Available')}")
        print(f"CVSS Version: {cve_data.get('cvss_version', 'Not Available')}")

        published_time = cve_data.get('published_time', 'Not Available')
        print(f"Published Time: {published_time if published_time != 'Not Available' else 'No Published Time Available'}")
        print(Fore.CYAN + "=" * 50)
        time.sleep(5)
    else:
        print(Fore.RED + f"Failed to fetch CVE details for {cve_id}.")

def indent_text(text, indent=4):
    """Indent multi-line text."""
    indented_text = ""
    lines = text.split('\n')
    for line in lines:
        indented_text += " " * indent + line + "\n"
    return indented_text.strip()

def main():
    while True:
        print(Fore.CYAN + "=" * 50)
        print(Fore.YELLOW + "Welcome to the Shodan CVE Info Tool")
        print(Fore.CYAN + "=" * 50)
        print(Fore.WHITE + "1. Enter Domain Name")
        print("2. Help")
        print("3. Exit")
        print(Fore.CYAN + "=" * 50)

        choice = input(Fore.YELLOW + "Select an option: ")

        if choice == '1':
            domain = input(Fore.YELLOW + "Enter the domain name: ")
            log_filename = f"{domain}.txt"

            # Create a buffer to capture output
            buffer = StringIO()
            dual_output = DualStream(sys.stdout, buffer)
            sys.stdout = dual_output  # Redirect print to both console and buffer

            print(Fore.CYAN + "=" * 50)
            print(Fore.YELLOW + f"Shodan CVE Info Tool Log - Domain: {domain}")
            print(Fore.CYAN + "=" * 50)

            ip_address = get_ip_from_domain(domain)

            if ip_address:
                get_shodan_info(ip_address)

            # After displaying to console, write the output buffer to the file
            with open(log_filename, "w") as log_file:
                log_file.write(dual_output.get_output())

        elif choice == '2':
            help_menu()

        elif choice == '3':
            print(Fore.GREEN + "Exiting tool. Goodbye!")
            break

        else:
            print(Fore.RED + "Invalid option, please choose a valid option (1, 2, or 3).")

if __name__ == "__main__":
    main()
