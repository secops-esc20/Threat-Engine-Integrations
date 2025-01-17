import requests
import json
import keyring
import sys 
import os
import re
from datetime import datetime


# Logging function
def log(message):
    log_file.write(message + "\n")
    print(message)

# Retrieve the API token from the local Windows Credential Manager database
def get_creds(service_id):
    try:
        password = keyring.get_credential(service_id, None)
        if not isinstance(password, keyring.credentials.SimpleCredential):
            log(f'Error: Windows Credentials Manager does not have an entry for Service_ID [{service_id}]')
            log('Either correct the ID in config.json or upload the API token(s) to WCM.')
            sys.exit(1)
        elif password is None:
            log(f"Error: No credentials found for {service_id}. Ensure the API token is stored in Windows Credential Manager.")
            sys.exit(1)
        else:
            return password.password
    except keyring.errors.KeyringError as e: 
        log(f"Error retrieving credentials for {service_id}: {e}")
        sys.exit(1)

# Load the config file and verify the json syntax is correct
def load_config(file):
    try: 
        return json.load(open('config.json', 'r'))
    except json.JSONDecodeError:
        print('Error: config.json syntax incorrect!')
        sys.exit(1)
    except FileNotFoundError:
        log("Error: unable to load config.json file!")
        sys.exit(1)
        
# Create the log file
def create_log_file(filename):
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
def validate_config_params(config_params, required_params):
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

# Pull a list of MISP IOCs that have been published in the past X hours
def get_misp_iocs():
    try:
        #Check if a custom filter was defined in the config
        if config_params['filter'] == "":
            q_filter = "{" + f'"type": "{config_params["type"]}", "published": true, "last": "{config_params["last"]}"' + "}"
        else:
            q_filter = "{" + f'"type": "{config_params["type"]}", "published": true, "last": "{config_params["last"]}", {config_params["filter"].replace("'", '"')}' + "}"

        # Pull IOCs based on query filters
        response = requests.post(f'{misp_url}/attributes/restSearch', headers=misp_headers, json=json.loads(q_filter), verify=False)
        print(response.text)
        
        # If the response failed or returned an unexpected result
        if not response.ok or 'response' not in response.json():
            log('Error: unable to retrieve IOCs from MISP!')
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

# Check if any of the IOCs were tagged for retraction
def validate(attributes):
    ioc = []
    for attribute in attributes:
        check_fire = False
        if 'Tag' in attribute:
            for tag in attribute['Tag']:
                if tag['name'] == 'retracted':
                    ioc.append([attribute['value'], 'retracted'])
                    check_fire = True
                
        # If the IoC was not tagged for retraction
        if not check_fire:
            ioc.append([attribute['value'], attribute['Event']['info']])
    return ioc

# Make sure the URL format is valid    
def is_valid_url(url):
    # Define the regex pattern for a valid URL
    url_pattern = re.compile(r'^(https?:\/\/)?'          # Optional scheme (http or https)
                             r'(([\w\-]+\.)+[\w\-]{2,})' # Domain name
                             r'(\:\d+)?'                 # Optional port
                             r'(\/[\w\-.~]*)*'           # Optional path
                             r'(\?[\w\-.~&=]*)?'         # Optional query
                             r'(#[\w\-]*)?$',            # Optional fragment
                             re.IGNORECASE)

    # Use the regex to check the URL
    return re.match(url_pattern, url) is not None

# Extract the domain(s) from the URLs and remove duplicates
def extract_domain(ioc):
    domains = []
    for url in ioc:
        ''' I was using this to help remove duplicates 
            and compress results to avoid pushing 100
            URLs that shared the same domain. It's
            wastefull but the data we recieve is so 
            inconsistant it wasn't worth the effort.
        if is_valid_url(url[0]):
            tmp = url[0] 
            tmp = tmp.replace('https://', '')
            tmp = tmp.replace('http://', '')
            if tmp.find('/') > -1:
                url[0] = tmp[ : tmp.find('/')]
            else: url[0] = tmp
        else: log(f"Error, invalid URL: {url[0]}")
        '''
        # Ensure the URL structure is valid and remove duplicates
        if is_valid_url(url[0]) and [url[0],url[1]] not in domains:
            domains.append([url[0],url[1]])
    return domains
    
# Display common error code descriptions
def api_error_code(code):
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
with create_log_file(today) as log_file:
    # Log the current date and time
    log(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))

    # Define the required config params
    required_params = ['fg_path', 'fg_wcm_id', 'fg_vdom', 'misp_path', 'misp_wcm_id', 'last', 'type', 'filter', 'exclude']

    # Make sure the required params are present in config.json
    validate_config_params(config_params, required_params)
        
    #Fortinet Gateway configurtion
    fng_url = config_params['fg_path']
    fng_token = get_creds(config_params['fg_wcm_id'])
    fng_headers = {
        'Authorization': f'Bearer {fng_token}',
        'Accept': 'application/json'
    }

    # MISP configuration
    misp_url = config_params['misp_path']
    misp_key = get_creds(config_params['misp_wcm_id'])
    misp_headers = {
        'Authorization': misp_key,
        'Accept': 'application/json'
    }

    # Query MISP
    log('Downloading MISP IOCs.')       
    returned_attributes = get_misp_iocs()

    # If the response contained no results, stop here
    if len(returned_attributes) == 0:
        log(f'No new IOCs published in the past {config_params["last"]}. Exiting.')
        sys.exit(1)

    # Validate by determining if any of the IOCs were tagged for retraction
    ioc = validate(returned_attributes)
        
    # Reduce URLs to just domains
    log('Filtering results.')
    domains = extract_domain(ioc)

    # Display some stats for the log file
    log('Some helpful stats:')
    log(f'  Total IOCs: {len(domains)}')
    counter = 0
    for domain in domains:
        if domain[1] == 'retracted':
            counter += 1
    log(f'  Retracted IoCs: {counter}')
    log(f'  Upload IOCs: {len(domains) - counter}')

    #Upload the domains to the fortinet webfilter
    if len(domains) > 0:
        for domain in domains:
            
            # Create the API parms and body
            query_params = {
                'vdom': config_params['fg_vdom']
            }
            body = {
                'url': domain[0],
                'status': 'enable',
                'comment': f'MISP: {domain[1]}',
                'rating': '26'
            }
            
            # If the IoC is tagged for retraction delete it
            if domain[1] == 'retracted':
                # Delete item to the FNG blocklist
                log(f'\nIoC tagged for retraction. Deleting [{domain[0]}]')
                try: 
                    response = requests.delete(f'{fng_url}/api/v2/cmdb/webfilter/ftgd-local-rating', headers=fng_headers, params=query_params, verify=False)  
                    if not response.ok:
                        log(f"Error: unable to delete [{domain[0]}].")
                        log(api_error_code(response.status_code))
                except requests.exceptions.RequestException as e:
                    log(f"Error during FortiOS API request: {e}")
                    sys.exit(1)
                    
            # Otherwise upload it
            else:
                # Add item to the FNG blocklist
                log(f'\nUploading IoC to blocklist [{domain[0]}]')
                try:
                    response = requests.post(f'{fng_url}/api/v2/cmdb/webfilter/ftgd-local-rating', headers=fng_headers, params=query_params, json=body, verify=False)  
                    if not response.ok:
                        log(f"Error: unable to upload [{domain[0]}].")
                        log(api_error_code(response.status_code))
                except requests.exceptions.RequestException as e:
                    log(f"Error during FortiOS API request: {e}")
                    sys.exit(1)
    else:
        log('No IOCs to upload.')
