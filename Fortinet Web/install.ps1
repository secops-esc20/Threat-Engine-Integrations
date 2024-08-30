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
        Invoke-WebRequest -Uri $githubFileUrl -OutFile $destinationPath -ErrorAction Stop
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
  "misp_path": "https://reg20misp02.esc20.com",
  "misp_wcm_id": "misp-api",
  "log_file_path": "logs/",
  "type": "url",
  "last": "1d"
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


function main {
    # Download the integration script from github
    Download-IntegrationScript -url "https://raw.githubusercontent.com/secops-esc20/Threat-Engine-Integrations/main/Fortinet%20Web/integration.py"

    # Get the Fortigate parameters and create the config file
    $fg_path = Read-Host -Prompt "Enter the Fortigate URL: "
    $fg_vdom = Read-Host -Prompt "Enter the Fortigate VDOM: "
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

    # Create a Task Scheduler event to run integration.py daily at 12 AM
    $pythonPath = (Get-Command python).Source
    $currentDirectory = Get-Location
    $scriptPath = '"' + (Join-Path -Path $currentDirectory -ChildPath "integration.py") + '"'
    $taskName = "MISP-Fortigate-Sync"
    $action = New-ScheduledTaskAction -Execute $pythonPath -Argument $scriptPath
    $trigger = New-ScheduledTaskTrigger -Daily -At 12:00AM
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable

    # Register the task
    Register-ScheduledTask -Action $action -Trigger $trigger -TaskName $taskName -Description "Runs MISP->Fortigate integration daily at 12 AM" -Settings $settings
    Write-Host "Scheduled task '$taskName' created."
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
    Write-Host "Uninstalling..."
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