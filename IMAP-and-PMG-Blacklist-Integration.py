
import imaplib
import email
import re
import requests
import warnings
import urllib3
from credentials import IMAP_SERVER, IMAP_USERNAME, IMAP_PASSWORD, PMG_API_URL, PMG_USERNAME, PMG_PASSWORD

# Suppress InsecureRequestWarning
warnings.filterwarnings("ignore", category=urllib3.exceptions.InsecureRequestWarning)

# ANSI escape codes for green color
GREEN = '\033[92m'
RESET = '\033[0m'

# Function to extract IP address from Received header
def extract_ip(received_header):
    # Regular expression to match IP address
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.findall(ip_pattern, received_header)
    if match:
        # Return the last IP address found (oldest received IP)
        return match[-1]
    return None

# Function to load whitelist IPs from file
def load_whitelist(filename):
    try:
        with open(filename, 'r') as file:
            return file.read().splitlines()
    except FileNotFoundError:
        return []

# Function to connect to the IMAP server, fetch messages, and extract source IPs
def fetch_source_ips_from_email():
    source_ips = set()  # Using a set to store unique IPs

    # Connect to the IMAP server
    imap = imaplib.IMAP4_SSL(IMAP_SERVER)
    imap.login(IMAP_USERNAME, IMAP_PASSWORD)

    # Select the Junk folder
    status, count = imap.select('Junk')
    if status != 'OK':
        print("Failed to select the Junk folder.")
        exit()

    # Search for the 10 latest messages
    status, message_ids = imap.search(None, 'ALL')
    if status != 'OK':
        print("Failed to search for messages.")
        exit()

    # Get the 10 latest messages
    message_ids = message_ids[0].split()[-10:]  # Get the 10 latest message IDs

    # Load whitelist IPs
    whitelist_ips = set(load_whitelist('whitelist_ips.txt'))  # Convert to set for faster lookup

    # Loop through each message and extract source IP
    for message_id in message_ids:
        status, message_data = imap.fetch(message_id, '(RFC822)')
        if status != 'OK':
            print(f"Failed to fetch message {message_id}")
            continue

        # Parse message
        raw_email = message_data[0][1]
        msg = email.message_from_bytes(raw_email)

        # Get source IP from headers
        received_headers = msg.get_all('Received')
        if received_headers:
            for received_header in received_headers[::-1]:
                source_ip = extract_ip(received_header)
                if source_ip and source_ip not in whitelist_ips:
                    source_ips.add(source_ip)
                    break  # Stop processing received headers after finding the oldest IP

    # Close the connection
    imap.close()
    imap.logout()

    return source_ips

# Function to get ticket and CSRF token
def get_ticket_and_csrf():
    login_url = f'{PMG_API_URL}/access/ticket'
    data = {
        'username': f'{PMG_USERNAME}@pmg',
        'password': PMG_PASSWORD,
    }
    try:
        response = requests.post(login_url, data=data, verify=False)
        response.raise_for_status()
        response_data = response.json().get('data')
        ticket = response_data.get('ticket')
        csrf_token = response_data.get('CSRFPreventionToken')
        return ticket, csrf_token
    except requests.exceptions.HTTPError as e:
        print(f"Failed to get ticket and CSRF token: {e}")
        return None, None

# Function to add IP objects to the blacklist
def add_ips_to_blacklist(ip_list):
    ticket, csrf_token = get_ticket_and_csrf()
    if ticket and csrf_token:
        headers = {'Cookie': f'PMGAuthCookie={ticket}', 'CSRFPreventionToken': csrf_token}
        add_ip_url = f'{PMG_API_URL}/config/ruledb/who/2/ip'
        try:
            for ip in ip_list:
                ip = ip.strip()
                data = {'ip': ip}
                response = requests.post(add_ip_url, headers=headers, data=data, verify=False)
                response.raise_for_status()
                print(f"{GREEN}IP {ip} has been successfully added to the blacklist.{RESET}")
        except requests.exceptions.HTTPError as e:
            print(f"Failed to add IPs to the blacklist: {e}")
    else:
        print("Failed to obtain ticket and CSRF token.")

# Function to retrieve the IDs of duplicate IP objects in the blacklist
def get_duplicate_blacklisted_object_ids():
    ticket, csrf_token = get_ticket_and_csrf()
    if ticket and csrf_token:
        headers = {'Cookie': f'PMGAuthCookie={ticket}', 'CSRFPreventionToken': csrf_token}
        blacklist_url = f'{PMG_API_URL}/config/ruledb/who/2/objects'
        try:
            response = requests.get(blacklist_url, headers=headers, verify=False)
            response.raise_for_status()
            blacklist_objects = response.json().get('data', [])
            
            # Find duplicate IPs
            ip_counts = {}
            for obj in blacklist_objects:
                ip = obj.get('ip')
                if ip:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            
            # Get IDs of duplicate IPs
            duplicate_ids = []
            for obj in blacklist_objects:
                ip = obj.get('ip')
                if ip and ip_counts[ip] > 1:
                    duplicate_ids.append((obj.get('id'), ip))
            
            return duplicate_ids
        except requests.exceptions.HTTPError as e:
            print(f"Failed to retrieve duplicate blacklisted objects: {e}")
            return []
    else:
        print("Failed to obtain ticket and CSRF token.")
        return []

# Function to remove all instances of duplicate IPs from the blacklist
def remove_all_duplicate_ips_from_blacklist():
    removed_ips = []
    duplicate_ids = get_duplicate_blacklisted_object_ids()
    if duplicate_ids:
        ticket, csrf_token = get_ticket_and_csrf()
        if ticket and csrf_token:
            headers = {'Cookie': f'PMGAuthCookie={ticket}', 'CSRFPreventionToken': csrf_token}
            delete_ip_url = f'{PMG_API_URL}/config/ruledb/who/2/objects/'
            try:
                for object_id, ip in duplicate_ids:
                    delete_url = f'{delete_ip_url}{object_id}'
                    response = requests.delete(delete_url, headers=headers, verify=False)
                    response.raise_for_status()
                    print(f"{GREEN}Duplicate IP with ID {object_id} has been successfully removed from the blacklist.{RESET}")
                    # Store removed IP for reapplication
                    removed_ips.append(ip)
            except requests.exceptions.HTTPError as e:
                print(f"Failed to remove duplicate IPs from the blacklist: {e}")
        else:
            print("Failed to obtain ticket and CSRF token.")
    else:
        print("No duplicate IPs found in the blacklist.")
    return removed_ips

# Function to add IP to blacklisted objects
def add_ip_to_blacklist(ip):
    ticket, csrf_token = get_ticket_and_csrf()
    if ticket and csrf_token:
        add_ip_url = f'{PMG_API_URL}/config/ruledb/who/2/ip?ip={ip}'
        headers = {'Cookie': f'PMGAuthCookie={ticket}', 'CSRFPreventionToken': csrf_token}
        try:
            response = requests.post(add_ip_url, headers=headers, verify=False)
            response.raise_for_status()
            print(f"{GREEN}IP {ip} has been successfully added to the blacklist.{RESET}")
        except requests.exceptions.HTTPError as e:
            print(f"Failed to add IP {ip} to the blacklist: {e}")
    else:
        print("Failed to obtain ticket and CSRF token.")

# Function to reapply one instance of each removed IP
def reapply_one_instance_of_removed_ips(removed_ips):
    reapplied_ips = set()  # to keep track of reapplied IPs
    for ip in removed_ips:
        if ip not in reapplied_ips:  # check if IP has already been reapplied
            add_ip_to_blacklist(ip)
            reapplied_ips.add(ip)

# Main function
def main():
    # Fetch source IPs from email messages
    source_ips = fetch_source_ips_from_email()

    # Save non-whitelisted unique source IPs to a text file
    with open('source_ips.txt', 'w') as file:
        for ip in source_ips:
            file.write(ip + '\n')

    print("Oldest non-whitelisted unique source IPs saved to source_ips.txt")

    # Read IP addresses from a local text file
    with open('source_ips.txt', 'r') as file:
        ip_list = file.readlines()

    # Add IP addresses to the blacklist
    add_ips_to_blacklist(ip_list)

    # Remove all instances of duplicate IPs from the blacklist
    removed_ips = remove_all_duplicate_ips_from_blacklist()
    
    # Reapply one instance of each removed IP
    reapply_one_instance_of_removed_ips(removed_ips)

if __name__ == '__main__':
    main()
