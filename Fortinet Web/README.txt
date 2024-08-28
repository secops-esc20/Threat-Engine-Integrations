
README: MISP to Fortinet Integration Script

Overview
--------
This script automates the process of downloading Indicators of Compromise (IOCs) from a MISP (Malware Information Sharing Platform) instance and uploading them to a Fortinet Gateway for web filtering. The script identifies new IOCs published within a specified time frame, filters them to extract domains, and updates the Fortinet web filter by either adding or removing these domains based on whether they have been retracted.

Files
-----
- intigration.py: The main Python script that handles the integration between MISP and Fortinet.
- config.json: The configuration file that contains the necessary parameters for the script to run, such as API paths, credentials, and log file paths.

Requirements
------------
- Python 3.x
- Modules:
  - requests: For making HTTP requests to the MISP and Fortinet APIs.
  - json: For handling JSON data.
  - keyring: For retrieving API tokens from the Windows Credential Manager.
  - sys, os, datetime: Standard Python libraries for system operations, file management, and date/time handling.

Configuration
-------------
config.json
-----------
This file should be located in the same directory as the script. It contains the following parameters:

fg_path: The URL of the Fortinet Gateway API.
fg_wcm_id: The identifier used in the Windows Credential Manager to retrieve the Fortinet API token.
fg_vdom: The VDOM (Virtual Domain) to which the domains will be uploaded in the Fortinet Gateway.
misp_path: The URL of the MISP instance.
misp_wcm_id: The identifier used in the Windows Credential Manager to retrieve the MISP API key.
log_file_path: The path where log files will be stored. The script will create a new log file each time it runs.
type: The type of IOCs to retrieve (e.g., url).
last: The time frame for retrieving recent IOCs (e.g., 1d for the last day).

Windows Credential Manager
--------------------------
Before running the script, ensure that the API tokens for MISP and Fortinet are securely stored in the Windows Credential Manager under the IDs specified in fg_wcm_id and misp_wcm_id.

Usage
-----
1. Setup Configuration:
   - Ensure that config.json is correctly populated with the necessary parameters.
   - Ensure that the required API tokens are stored in the Windows Credential Manager.

2. Run the Script:
   - Execute the script using Python:
     python intigration.py
   - The script will create a log file in the specified log_file_path directory, named with the current date (YYYYMMDD format).

3. Review Logs:
   - Check the log file in the logs/ directory for a detailed output of the script’s actions, including any errors or issues encountered.

Error Handling
--------------
The script includes comprehensive error handling for common issues such as:
- Missing or malformed config.json file.
- Issues retrieving credentials from the Windows Credential Manager.
- Problems communicating with the MISP or Fortinet APIs.
- File permissions errors when creating or writing to log files.

Common API error codes are translated into human-readable messages and logged for easy troubleshooting.

Logging
-------
The script logs each step of its process, including:
- The start and end time of the script run.
- The number of IOCs retrieved, retracted, and uploaded.
- Detailed error messages in case of failures.

Security Considerations
-----------------------
- API tokens should be securely stored in the Windows Credential Manager and should not be hard-coded or exposed in the script.
- Log files should be monitored to ensure they do not inadvertently expose sensitive information.

Support
-------
For any issues or questions, please contact your system administrator or the script maintainer.
