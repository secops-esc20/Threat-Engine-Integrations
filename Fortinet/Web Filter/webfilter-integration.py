import os
import re
import sys
import json
from datetime import datetime

import requests
import keyring

from typing import TextIO

"""
Threat Intelligence Integration Script
--------------------------------------
This script integrates with MISP (Malware Information Sharing Platform) to retrieve and validate 
Indicators of Compromise (IOCs) and update a security appliance’s blocklist.

Author: Samuel Bravo  
Date: February 2025  
"""

# Logging function
def log(message: str) -> None:
    try:
        log_file.write(message + "\n")
        print(message)
    except: pass

# Retrieve the API token from the local Windows Credential Manager database
def get_creds(service_id: str) -> tuple[str, str]:
    try:
        creds = keyring.get_credential(service_id, None)
        if not isinstance(creds, keyring.credentials.SimpleCredential):
            log(f'Error: Windows Credentials Manager does not have an entry for Service_ID [{service_id}]')
            log('Either correct the ID in config.json or upload the API token(s) to WCM.')
            sys.exit(1)
        elif creds is None:
            log(f"Error: No credentials found for {service_id}. Ensure the API token is stored in Windows Credential Manager.")
            sys.exit(1)
        else:
            return creds.username, creds.password
    except keyring.errors.KeyringError as e: 
        log(f"Error retrieving credentials for {service_id}: {e}")
        sys.exit(1)

# Load the config file and verify the json syntax is correct
def load_config(file: str) -> None:
    try: 
        return json.load(open(file, 'r'))
    except json.JSONDecodeError:
        print('Error: config.json syntax incorrect!')
        sys.exit(1)
    except FileNotFoundError:
        print("Error: unable to load config.json file!")
        sys.exit(1)
        
# Create the log file
def create_log_file(filename: str, config_params: dict) -> TextIO:
    try:
        # Make sure the path to the log file was defined
        if 'log_file_path' not in config_params:
            print("Error: configuration file is missing [log_file]!")
            sys.exit(1)  
        # If the log folder doesn't exist, create it
        elif not os.path.exists(config_params['log_file_path']): 
            try: 
                os.mkdir(config_params['log_file_path'])
            except OSError as e: 
                print('Error: unable to create log folder!')
                print(e)
                sys.exit(1)
        # Check the log foler path permissions  
        if not os.access(config_params['log_file_path'], os.W_OK):
            log("Error: No write permissions for the specified log file path.")
            sys.exit(1)
        else:
            return open(config_params['log_file_path'] + filename + '.txt', 'w+')
    except IOError as e:
        log(f"Error: unable to create log file: {e}")
        sys.exit(1)
        
# Make sure all the required parameters are in config.json    
def validate_config_params(config_params: dict, required_params: str) -> None:
    try:
        # Make sure all the required keys are present and assigned a value
        missing_params = []
        for param in required_params:
            if param not in config_params:
                missing_params.append(param)
            elif config_params[param] == '' and param not in ['filter', 'exclude']: #filter and exclude are optional and by default are empty
                missing_params.append(param)
        
        # If not, log the missing parameters and exit
        if missing_params:
            log(f"Error: configuration file is missing the following parameters: {', '.join(missing_params)}")
            sys.exit(1)
    except:
        log("Error: unable to load configuration file!")
        sys.exit(1)

# Pull a list of MISP iocs that have been published in the past X hours
def get_misp_iocs() -> dict:
    try:
        #Check if a custom filter was defined in the config
        if config_params['filter'] == "":
            q_filter = "{" + f'"type": "{config_params["type"]}", "published": true, "last": "{config_params["last"]}"' + "}"
        else:
            q_filter = "{" + f'"type": "{config_params["type"]}", "published": true, "last": "{config_params["last"]}", {config_params["filter"].replace("'", '"')}' + "}"
        log(f"Query filter: {q_filter}")
        
        # Pull iocs based on query filters
        response = requests.post(f'{misp_url}/attributes/restSearch', headers=misp_headers, json=json.loads(q_filter), verify=False)
        
        # If the response failed or returned an unexpected result
        if not response.ok or 'response' not in response.json():
            log('Error: unable to retrieve iocs from MISP!')
            log(api_error_code(response.status_code))
            sys.exit(1)
        # If the request was successful, validate the response
        else:
            try:
                json_response = response.json()
                return json_response.get('response', {}).get('Attribute', [])
            except (ValueError, KeyError):
                log("Error: received an unexpected or malformed JSON response from MISP!")
                log(f"Response: {response.text}")
                sys.exit(1)
    except requests.exceptions.RequestException as e:
        log(f"Error during MISP request: {e}")
        sys.exit(1)
   
# Make sure the URL format is valid    
def is_valid_format(url: str) -> bool:
    try:
        # Define the regex pattern for a valid URL
        url_pattern = re.compile(
            r'^(https?:\/\/)?'            # Mandatory http or https
            r'(([\w\-]+\.)+[\w\-]{2,}|'   # Domain OR
            r'\b(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'  # IPv4 first octet
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'    # IPv4 second octet
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\.'    # IPv4 third octet
            r'(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)\b)'   # IPv4 fourth octet
            r'(\:\d+)?'                    # Optional port
            r'(\/[~\w\-.%=@]*)*'           # Path: Allows `~`, `-`, `.`, `_`, `%`, `=`, `@`
            r'(\?[\w\-.~&=%@]*)?'          # Query: Supports `@`, `=`, `%`, `&`
            r'(#[\w\-]*)?$',               # Optional fragment
            re.IGNORECASE
        )

        # Use the regex to check the URL
        valid = re.match(url_pattern, url) is not None
        return valid
    except: return False

# Check make sure the IOCs were formatted correctly and were not tagged for retraction
def validate(attributes: dict) -> list:
    iocs = []

    for attribute in attributes:
        #Make sure the attribute's syntax or formatting is correct before futher processing
        valid = True
        if not is_valid_format(attribute['value']):
            valid = False
            log(f"Removing illegal attribute: {attribute['value']}")
        
        #Check if the attribute has any tags, if so does it have the retracted tag
        check_fire = False
        if 'Tag' in attribute:
            for tag in attribute['Tag']:
                if tag['name'] == 'retracted':
                    iocs.append([attribute['value'], 'retracted'])
                    check_fire = True
                
        # If the iocs was not tagged for retraction and was formatted correctly
        if not check_fire and valid:
            iocs.append([attribute['value'], attribute['Event']['info']])
    return iocs
    
# Display common error code descriptions
def api_error_code(code: int) -> str:
    codes = {
        400: 'Bad Request: Request cannot be processed by the API',
        401: 'Not Authorized: Request without successful login session',
        403: 'Bad Forbidden: Request is missing CSRF token or administrator is missing access profile permissions.',
        404: 'Resource Not Found: Unable to find the specified resource.',
        405: 'Method Not Allowed: Specified HTTP method is not allowed for this resource.',
        413: 'Failed Dependency: Fail dependency can be duplicate resource, missing required parameter, missing required attribute, invalid attribute value',
        424: 'Bad Request: Request cannot be processed by the API',
        429: 'Access temporarily blocked: Maximum failed authentications reached. The offended source is temporarily blocked for certain amount of time.',
        500: 'Internal Server Error: Internal error when processing the request'
    }
    if code in codes:
        return f"{code}: {codes[code]}"
    else:
        return f'{code}: unknown error code'

# Display some helpful stats       
def show_stats(iocs: list) -> None:
    log('Some helpful stats:')
    log(f'  Total iocs: {len(iocs)}')
    counter = 0
    for ioc in iocs:
        if ioc[1] == 'retracted':
            counter += 1
    log(f'  Retracted iocs: {counter}')
    log(f'  Upload iocs: {len(iocs) - counter}')

class vendor:
    def __init__(self):
        self.required_config_params = ['fg_path', 'fg_wcm_id', 'fg_vdom', 'misp_path', 'misp_wcm_id', 'last', 'type', 'filter', 'exclude']
        self.username = ""
        self.password = ""
        self.wcm_service_id = ""
        self.api_token = ""
        self.api_root = ""
        self.api_endpoint = "cmdb/webfilter/ftgd-local-rating"
        self.api_header = ""
        self.api_query_params = ""
        self.api_body = ""
    
    def update_api_token(self):
        self.api_token = self.password
        
    def update_api_header(self):
        self.api_header = {
        'Authorization': f'Bearer {self.api_token}',
        'Accept': 'application/json'
        }
        
    def update_api_query_params(self, vdom):
        self.api_query_params = {'vdom': vdom}
        
    def update_api_body(self, ioc, comment):
        self.api_body = {
                'url': ioc,
                'status': 'enable',
                'comment': comment,
                'rating': '26'
               }
               
    def delete_ioc(self):
        return requests.delete(f'{self.api_root}/{self.api_endpoint}', headers=self.api_header, params=self.api_query_params, verify=False)
        
    def add_ioc(self):
        return requests.post(f'{self.api_root}/{self.api_endpoint}', headers=self.api_header, params=self.api_query_params, json=self.api_body, verify=False)

# Retrieve the config file parameters        
config_params = load_config('config.json')
        
# Verify the json file is correctly structured
if not isinstance(config_params, dict):
    log("Error: configuration file structure is invalid!")
    sys.exit(1)
    
# Get todays date in YYYYMMDD format
today = datetime.today()
today = today.strftime('%Y%m%d')

# Try to create the log file using YYYYMMDD as the filename 
with create_log_file(today, config_params) as log_file:
    # Log the current date and time
    log(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    
    # Create a vendor class
    vendor_params = vendor()

    # Make sure the required params are present in config.json
    validate_config_params(config_params, vendor_params.required_config_params)
        
    #API Gateway configurtion
    vendor_params.api_root = config_params['fg_path']
    vendor_params.username, vendor_params.password = get_creds(config_params['fg_wcm_id'])
    vendor_params.update_api_token()
    vendor_params.update_api_header()


    # MISP configuration
    misp_url = config_params['misp_path']
    misp_key = get_creds(config_params['misp_wcm_id'])[1]
    misp_headers = {
        'Authorization': misp_key,
        'Accept': 'application/json'
    }

    # Query MISP
    log('Downloading MISP iocs.')       
    returned_attributes = get_misp_iocs()
    log("!")

    # If the response contained no results, stop here
    if len(returned_attributes) == 0:
        log(f'No new iocs published in the past {config_params["last"]}. Exiting.')
        sys.exit(1)

    # Check if any of the IOCs were tagged for retraction
    log('Validating IOCs.')
    iocs = validate(returned_attributes)
    log("!")

    # Display some stats for the log file
    show_stats(iocs)
    log("!")

    #Upload the iocs to the appliance
    if len(iocs) > 0:
        for ioc in iocs:
            
            # Create the API params and body
            vendor_params.update_api_query_params(config_params['fg_vdom'])
            vendor_params.update_api_body(ioc[0], f'MISP: {ioc[1]}')

            
            # If the iocs is tagged for retraction delete it
            if ioc[1] == 'retracted':
                # Delete the ioc from the appliance's blocklist
                log(f'\niocs tagged for retraction. Deleting [{ioc[0]}]')
                try: 
                    response = vendor_params.delete_ioc()
                    if not response.ok:
                        log(f"Error: unable to delete [{ioc[0]}].")
                        log(api_error_code(response.status_code))
                except requests.exceptions.RequestException as e:
                    log(f"Error during FortiOS API request: {e}")
                    sys.exit(1)
                    
            # Otherwise upload it
            else:
                # Add item to the appliance blocklist
                log(f'Uploading iocs to blocklist [{ioc[0]}]')
                try:
                    response = vendor_params.add_ioc()  
                    if not response.ok:
                        log(f"  Error: unable to upload [{ioc[0]}]")
                        log("  " + api_error_code(response.status_code))
                except requests.exceptions.RequestException as e:
                    log(f"Error during FortiOS API request: {e}")
                    sys.exit(1)
    else:
        log('No iocs to upload.')
