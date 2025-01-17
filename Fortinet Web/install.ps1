# Function to determine the currenlty supported TLS version
function check_tls_ver {
    # Get the currently supported TLS version(s)
    $currentTLS = [Net.ServicePointManager]::SecurityProtocol

    # Check if TLS 1.0 or TLS 1.1 is included
    if ($currentTLS -band [Net.SecurityProtocolType]::Tls -or $currentTLS -band [Net.SecurityProtocolType]::Tls11) {
        Write-Host "WARNING: TLS 1.0 or 1.1 is currently enabled. Both version are deprecated and should be disabled." -ForegroundColor Red
        Write-Host "TLS 1.2 or 1.3 is required for this application to function securly. TLS 1.3 requires PowerShell Core (7+) with .NET Core/6+" -ForegroundColor Red
        Write-Host "You can enable TLS 1.2/1.3 using one of the following commands:" -ForegroundColor Red
        Write-Host " # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12" -ForegroundColor Red
        Write-Host " # [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls13" -ForegroundColor Red
        exit 1
    }
}


# Function to add API tokens to Windows Credential Manager (WCM)
function Add-ApiTokenToWCM {
    param(
        [string]$PromptMessage,
        [string]$TargetName,
        [string]$UserName
    )
    
    try {
        # Prompt the user for the API token
        $Password = Read-Host -Prompt $PromptMessage -AsSecureString

        # Convert the secure string password to plain text
        $PlainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password))

        # Add the credential to Windows Credential Manager
        cmdkey /generic:$TargetName /user:$UserName /pass:$PlainPassword

        Write-Host "Credential for $TargetName stored successfully."
    } catch {
        Write-Host "Error: Unable to store the credential for $TargetName. $_" -ForegroundColor Red
        exit 1
    }
}

# Function to check if Python is installed
function Check-PythonInstalled {
    try {
        $pythonVersion = python --version 2>&1
        if ($pythonVersion -match "Python (\d+\.\d+\.\d+)") {
            Write-Host "Python is installed. Version: $($matches[1])"
            return $true
        } else {
            return $false
        }
    } catch {
        return $false
    }
}

# Function to download and install Python
function Install-Python {
    $pythonInstallerUrl = "https://www.python.org/ftp/python/3.12.5/python-3.12.5-amd64.exe"
    $installerPath = "$env:TEMP\python-installer.exe"

    try {
        # Download the Python installer
        Write-Host "Downloading Python installer..."
        Invoke-WebRequest -Uri $pythonInstallerUrl -OutFile $installerPath -ErrorAction Stop

        # Install Python silently
        Write-Host "Installing Python..."
        Start-Process -FilePath $installerPath -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1" -Wait

        # Clean up the installer file
        Remove-Item $installerPath
        Write-Host "Python has been installed successfully."
    } catch {
        Write-Host "Error: Failed to download or install Python. $_" -ForegroundColor Red
        exit 1
    }
}

# Function to install required Python libraries
function Install-PythonLibraries {
    $packages = @("requests", "keyring")

    foreach ($package in $packages) {
        Write-Host "Installing $package..."
        try {
            python -m pip install $package -q
        } catch {
            Write-Host "Error: Failed to install $package. $_" -ForegroundColor Red
            exit 1
        }
    }
    Write-Host "All required libraries have been installed."
}

# Function to download the integration script
function Download-IntegrationScript {
    param(
    [string]$url
    )
    $githubFileUrl = $url
    $destinationPath = "integration.py"

    try {
        # Download the integration script
        Invoke-WebRequest -Uri $githubFileUrl -OutFile $destinationPath -ErrorAction Stop
        # Download the limited use license agreement
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/secops-esc20/Threat-Engine-Integrations/main/Fortinet%20Web/LICENSE.txt" -OutFile "LICENSE.txt"
        #Download the readme
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/secops-esc20/Threat-Engine-Integrations/main/Fortinet%20Web/README.txt" -OutFile "README.txt"
        Write-Host "File downloaded successfully to $destinationPath"
    } catch {
        Write-Host "Error: Failed to download the integration script. $_" -ForegroundColor Red
        exit 1
    }
}

# Function to create the config file
function Create-ConfigFile {
    param(
        [string]$fg_path,
        [string]$fg_vdom
    )

    $filePath = "config.json"

    $default_config = @"
{
  "fg_path": "$fg_path",
  "fg_vdom": "$fg_vdom",
  "fg_wcm_id": "forti-api",
  "misp_path": "https://threatengine2.esc20.net",
  "misp_wcm_id": "misp-api",
  "log_file_path": "logs/",
  "type": "url",
  "last": "1d",
  "filter": "",
  "exclude": ""
}
"@

    try {
        # Create and write the config file
        New-Item -Path $filePath -ItemType File -Force
        Set-Content -Path $filePath -Value $default_config
        Write-Host "Config file created at $filePath"
    } catch {
        Write-Host "Error: Failed to create the config file. $_" -ForegroundColor Red
        exit 1
    }
}

function Display-Help {
    Write-Host "Description:"
    Write-Host "The integrations script automates the process of downloading Indicators of Compromise (IOCs) from a MISP (Malware Information Sharing Platform) instance and uploading them to a Fortinet Gateway for web filtering. The script identifies new IOCs published within a specified time frame, filters them to extract domains, and updates the Fortinet web filter by either adding or removing these domains based on whether they have been retracted."
    Write-Host ""
    Write-Host "Run install.ps1 without arguments to run through the full install process."
    Write-Host "  -help: display this info page."
    Write-Host "  -update: update the integration.py script."
    Write-Host "  -uninstall: uninstall python and remove the task scheduler task."
    Write-Host "  -update-misp-apikey: update the WCM entry for misp-api."
    Write-Host "  -update-forti-apikey: update the WCM entry for forti-api."
    Write-Host "Example: \.install.ps1 -update "
}

# Create a Task Scheduler event
function createTask {
    param(
        [string]$scriptName,
        [string]$taskName,
        [string]$taskDescription
    )
    try{
        # Create the task parameters
        $pythonPath = (Get-Command python).Source
        $currentDirectory = Get-Location
        $scriptPath = '"' + (Join-Path -Path $currentDirectory -ChildPath $scriptName) + '"'
        $action = New-ScheduledTaskAction -Execute $pythonPath -Argument $scriptPath -WorkingDirectory $currentDirectory
        $trigger = New-ScheduledTaskTrigger -Daily -At 12am
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -DontStopOnIdleEnd
        $userSID = (Get-WmiObject -Class Win32_UserAccount -Filter "Name='$env:USERNAME'").SID
        $principal = New-ScheduledTaskPrincipal -UserId $userSID -LogonType S4U -RunLevel Highest
        
        # Register the task
        Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description $taskDescription -Settings $settings -Principal $principal
        Write-Host "Scheduled task '$taskName' created."
    }
    catch {
        Write-Host "Error creating scheduled task: $_"
    }    
}

function uninstall {
    # Confirm Uninstall
    $answer = Read-Host -Prompt "Proceed with uninstall? (Y/N)"
    if ($answer -match '^(Y|y|yes)$') {
        Write-Host "Proceeding with uninstall."
    } else {
        Write-Host "Aborting uninstall."
        exit 1
    }
    
    # Delete the sync task
    if (Get-ScheduledTask -TaskName "MISP-Fortigate-Sync" -ErrorAction SilentlyContinue) {
        Write-Host "Deleting scheduled task: MISP-Fortigate-Sync"
        Unregister-ScheduledTask -TaskName "MISP-Fortigate-Sync" -Confirm:$false
    } else {
        Write-Host "Scheduled task 'MISP-Fortigate-Sync' not found."
    }
    
    # Delete the updater task
    if (Get-ScheduledTask -TaskName "MISP-Fortigate-Integration-Updater" -ErrorAction SilentlyContinue) {
        Write-Host "Deleting scheduled task: MISP-Fortigate-Integration-Updater"
        Unregister-ScheduledTask -TaskName "MISP-Fortigate-Integration-Updater" -Confirm:$false
    } else {
        Write-Host "Scheduled task 'MISP-Fortigate-Integration-Updater' not found."
    }
    
    # Uninstall all Python versions
    Write-Host "Uninstalling Python versions..."
    Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*Python*" } | ForEach-Object {
        Write-Host "Uninstalling: $($_.Name)"
        $_.Uninstall() | Out-Null
    }
    
    # Delete the integration script and text files
    $filesToDelete = @("integration.py", "*.txt", "*.json")
    foreach ($file in $filesToDelete) {
        if (Test-Path $file) {
            Write-Host "Deleting file: $file"
            Remove-Item $file -Force
        } else {
            Write-Host "File not found: $file"
        }
    }
    
    Write-Host "Uninstallation completed."
}

function main {
    # Ensure TLS 1.2 or 1.3 is configured, abort if not
    check_tls_ver
    
    # Download the integration script from github
    Download-IntegrationScript -url "https://raw.githubusercontent.com/secops-esc20/Threat-Engine-Integrations/main/Fortinet%20Web/integration.py"

    # Get the Fortigate parameters and create the config file
    $fg_path = Read-Host -Prompt "Enter the Fortigate URL"
    $fg_vdom = Read-Host -Prompt "Enter the Fortigate VDOM"
    Create-ConfigFile -fg_path $fg_path -fg_vdom $fg_vdom

    # Store API keys in Windows Credential Manager
    Add-ApiTokenToWCM -PromptMessage "Enter Fortigate API key" -TargetName "forti-api" -UserName "forti-api"
    Add-ApiTokenToWCM -PromptMessage "Enter MISP API key" -TargetName "misp-api" -UserName "misp-api"

    # Check if Python is installed, if not, install it
    if (-not (Check-PythonInstalled)) {
        Write-Host "Python is not installed. Proceeding with installation..."
        Install-Python
    }

    # Update pip
    try {
        python -m pip install --upgrade pip
    } catch {
        Write-Host "Error: Failed to update pip. $_" -ForegroundColor Red
        exit 1
    }

    # Install required Python libraries
    Write-Host "Installing required Python libraries..."
    Install-PythonLibraries
    
    # Have the user input the time for the sync to occur daily
    $triggerTime = Read-Host -Prompt "Enter the time you'd like the daily sync to occur at (Ex 12am)"
    
    # Create the recurring task to automatically run the sync
    Write-Host "Create the MISP->Fortigate task scheduler event."
    createTask -taskName "MISP-Fortigate-Sync" -scriptName "integration.py" -taskDescription "Runs MISP->Fortigate integration daily."

    # Create the recurring task to automatically run the sync
    Write-Host "Create the automatic updates task scheduler event."
    createTask -taskName "MISP-Fortigate-Integration-Updater" -scriptName "install.ps1 -update" -taskDescription "Runs MISP->Fortigate integration updater daily."
}

# If no arguments were passed, run main
if ($args.Count -eq 0) {
    main
}
elseif ($args.Count -gt 1) {
    Write-Host "Error: too many arguments given!"
}
elseif ($args[0] -eq "-help") {
    Display-Help
}
elseif ($args[0] -eq "-update"){
    Download-IntegrationScript
}
elseif ($args[0] -eq "-uninstall"){
    uninstall
}
elseif ($args[0] -eq "-update-misp-apikey"){
    Add-ApiTokenToWCM -PromptMessage "Enter MISP API key" -TargetName "misp-api" -UserName "misp-api"
}
elseif ($args[0] -eq "-update-forti-apikey"){
    Add-ApiTokenToWCM -PromptMessage "Enter Fortigate API key" -TargetName "forti-api" -UserName "forti-api"
}
else {
    Write-Host "Error! Unknown argument, use -help for assistance."
}