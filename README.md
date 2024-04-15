
# IMAP and PMG Blacklist Integration

## Overview

This script is designed to connect to an IMAP (Internet Message Access Protocol) server to parse emails in the spam/junk folder and extract the origin IP addresses. It then connects to a Proxmox Mail Gateway (PMG) and adds these extracted IP addresses to the blacklist. Additionally, it ensures that only unique IP addresses are added to the blacklist and removes any duplicates.

## Prerequisites

Before using this script, ensure you have the following prerequisites:

1. **Python Environment**: This script is written in Python. Make sure you have Python installed on your system.

2. **Dependencies**: Install the required dependencies using the following command:
    ```
    pip install imaplib email requests
    ```

3. **Credentials**: You need to have credentials for both the IMAP server and the Proxmox Mail Gateway. Create a file named `credentials.py` in the same directory as the script with the following content:
    ```python
    IMAP_SERVER = 'your_imap_server_address'
    IMAP_USERNAME = 'your_imap_username'
    IMAP_PASSWORD = 'your_imap_password'
    
    PMG_API_URL = 'your_pmg_api_url'
    PMG_USERNAME = 'your_pmg_username'
    PMG_PASSWORD = 'your_pmg_password'
    ```

4. **Whitelist IPs**: If there are any IP addresses that should not be added to the blacklist, list them in a file named `whitelist_ips.txt` in the same directory as the script, with each IP address on a new line.

## Usage

To use the script, follow these steps:

1. **Run the Script**: Execute the script using the following command:
    ```
    python script_name.py
    ```

2. **View Outputs**:
    - The script will print status messages to the console indicating the progress of fetching and processing emails, adding IPs to the blacklist, and removing duplicates.
    - The oldest non-whitelisted unique source IPs will be saved to a file named `source_ips.txt` in the same directory as the script.

## Important Notes

- **Security**: Ensure that the credentials file (`credentials.py`) and any sensitive information are kept secure and not shared publicly.
- **Whitelist IPs**: Review the `whitelist_ips.txt` file to ensure that any IPs listed there should not be blacklisted.
- **Error Handling**: The script includes error handling for various scenarios, but ensure proper monitoring and logging in a production environment.

## Contributors

- Piotr Esse

## License

This project is licensed under the [MIT License](LICENSE).

---
Please replace `[Your Name]` and `[Your Email]` with appropriate values. Let me know if you need further assistance!
