<#
Version 1.4

1. Run Powershell as an admin.
    Right-click Start button and select Terminal (Admin).
2. Connect USB drive with the script on it. 
    Note: Script should be placed on all imaging USB drives in a Scripts folder.
3. Run the script:
    Look for Run-AssessPC.cmd in the same folder and run that. If you don't have that, run the following command:
    powershell.exe -ExecutionPolicy Bypass -File "D:\Scripts\Assess-PC.ps1"
    Note: Path to file in above command might change depending on the USB drive letter, script location or script name.
4. View results from script. It will let you know if everything looks good or any specific issues that it finds (missing process, missing file, etc.).
#>

# functions
Function Test-SessionPrivileges
{
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentSessionIsAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

    if ($currentSessionIsAdmin -ne $true)
    {
        Write-Warning ("Session is not running with admin priviledges. `n" +
        "Certain checks will not work correctly. `n" +
        "1. Open Powershell as admin. `n" +
        "2. Enter command: Powershell.exe -ExecutionPolicy Bypass -File `"scriptpath\scriptname.ps1`" ")

        Read-Host "Press Enter to continue."
    }
}

function Show-TimeStamp
{
    $timeStamp = Get-Date -Format yyyy-MM-dd-hh-mm
    Write-Host $timestamp -ForegroundColor DarkCyan
}

function Confirm-WindowsVersionInfo
{
    $edition = Get-CimInstance -ClassName 'Win32_OperatingSystem' | Select-Object -ExpandProperty Caption
    $edition = $edition.Replace("Microsoft ", "")
    $versionInfo = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\'
    if ($edition -eq "Windows 11 Pro")
    {
        Write-Host "$edition $($versionInfo.DisplayVersion) (OS Build $($versionInfo.CurrentBuildNumber).$($versionInfo.UBR))" -ForegroundColor Green
    }
    else
    {
        Write-Host "$edition $($versionInfo.DisplayVersion) (OS Build $($versionInfo.CurrentBuildNumber).$($versionInfo.UBR))" -ForegroundColor Yellow
    }
    # Version numbers for Win 11: https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information
    # Version numbers for Win 10: https://learn.microsoft.com/en-us/windows/release-health/release-information
}

function Show-UserProfiles
{
    Write-Host "User profiles:" -ForegroundColor DarkCyan
    $users = Get-CimInstance -ClassName "Win32_UserProfile" | Where-Object { $_.LocalPath -ilike 'C:\Users\*' } | Select-Object -Property @("LocalPath", "LastUseTime")
    $users | Out-Host
    if ($users.Count -gt 2)
    {
        Write-Warning "There are more than 2 user profiles on this PC."
    }
}

function Confirm-BIOSVersionInfo
{
    $biosVersion = Get-CimInstance -Class Win32_BIOS | Select-Object -ExpandProperty "SMBIOSBIOSVersion"

    [bool]$parseVersionNumber = Test-IsModelToCheckForChargingFlaw # will parse the version number if it's one of the models we need to check

    if (-not($parseVersionNumber))
    {
        Write-Host "BIOS version: $biosVersion" -ForegroundColor Green
        return
    }

    $parsedBIOSVersion = Select-String -InputObject $biosVersion -Pattern '(?<=\()\d*\.\d*' # getting distilled version number from string with regex
    
    if ($null -eq $parsedBIOSVersion) # biosVersion was in unexpected format
    {
        Write-Host "BIOS version: $biosVersion" -ForegroundColor Green
        return
    }

    [int]$biosVersionNumber = $parsedBIOSVersion.Matches.Value

    if ($biosVersionNumber -ge 1.51)
    {
        Write-Host "BIOS version is at least 1.51: $biosVersion" -ForegroundColor Green
    }
    else
    {
        Write-Host ("BIOS version is: $biosVersion. Should be at least 1.51 for this model of PC.`n" +
        "See article: https://support.lenovo.com/us/en/solutions/ht514028-critical-bios-and-pdfw-update-for-usb-c-port-charging-thinkpad-e14-gen-2-and-thinkpad-e15-gen2") -ForegroundColor Red
    }
}

function Test-IsModelToCheckForChargingFlaw
{
    $affectedModels = @("20TAS06700", "20TBS06700", "20TDS06700", "20TES06700") # E15 Gen 2 laptops. Types: 20TA, 20TB, 20TD, and 20TE.
    $thisModel = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty "Model"

    foreach ($model in $affectedModels)
    {
        if ($model -eq $thisModel)
        {
            return $true
        }
    }

    return $false
}

function Confirm-DeviceNamedCorrectly
{
    $serialNumber = Get-SerialNumber

    if ($env:COMPUTERNAME -eq "LAPTOP-$serialNumber")
    {
        Write-Host "Device is named correctly: $($env:COMPUTERNAME)" -ForegroundColor Green
    }
    else
    {
        Write-Host ("Device named incorrectly. `n" +
            "`tExpected value: LAPTOP-$serialNumber `n" +
            "`tActual value: $($env:COMPUTERNAME)") -ForegroundColor Red
    }
}

function Get-SerialNumber
{
    return Get-CimInstance -ClassName Win32_BIOS | Select-Object -ExpandProperty SerialNumber
}

function Confirm-JoinedToAzureAD
{
    $deviceStateInfo = (dsregcmd /status)
    foreach ($string in $deviceStateInfo)
    {
        if ($string -imatch ".*AzureADJoined.*")
        {
            if ($string -imatch ".*AzureAdJoined : YES.*")
            {
                Write-Host "Joined to Azure AD." -ForegroundColor Green                
            }
            else
            {
                Write-Host "NOT joined to Azure AD." -ForegroundColor Red
            }
        }
    }
}

function Confirm-FreshServiceReady
{
    $isFreshServiceReady = $true

    if ((Confirm-FreshServiceProcessesRunning) -eq $false)
    {
        $isFreshServiceReady = $false
    }
    if ((Confirm-FreshServiceFilesExist) -eq $false)
    {
        $isFreshServiceReady = $false
    }

    if ($isFreshServiceReady)
    {
        Write-Host "FreshService is ready." -ForegroundColor Green
    }
    else
    {
        Write-Host "Found issue with FreshService." -ForegroundColor Red
    }
}

function Confirm-FreshServiceProcessesRunning
{
    $allProcessesRunning = $true
    if ((Confirm-ProcessRunning "FSAgentService") -eq $false)
    {
        $allProcessesRunning = $false
    }
    return $allProcessesRunning
}

function Confirm-ProcessRunning($processName)
{
    if ($null -eq (Get-Process -Name $processName -ErrorAction SilentlyContinue))
    {
        Write-Host "Process missing: $processName" -ForegroundColor Red
        return $false
    }
    return $true
}

function Confirm-FreshServiceFilesExist
{
    $allFilesAndFoldersExist = $true
    if ((Confirm-FileOrFolderExists "C:\Program Files (x86)\Freshdesk") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    return $allFilesAndFoldersExist
}

function Confirm-FileOrFolderExists($itemName)
{    
    if ($null -eq (Get-Item -Path $itemName -Force -ErrorAction SilentlyContinue))
    {
        Write-Host "File/Folder missing: $itemName" -ForegroundColor Red
        return $false
    }
    return $true
}

function Confirm-SophosReady
{
    $isSophosReady = $true

    if ((Confirm-SophosProcessesRunning) -eq $false)
    {
        $isSophosReady = $false
    }
    if ((Confirm-SophosFilesExist) -eq $false)
    {
        $isSophosReady = $false
    }

    if ($isSophosReady)
    {
        Write-Host "Sophos is ready." -ForegroundColor Green
    }
    else
    {
        Write-Host "Found issue with Sophos." -ForegroundColor Red
    }
}

function Confirm-SophosProcessesRunning
{
    $allProcessesRunning = $true
    if ((Confirm-ProcessRunning "SophosFileScanner") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "SophosFS") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "SophosHealth") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "SophosNetFilter") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "SophosNtpService") -eq $false)
    {
        $allProcessesRunning = $false
    }
    return $allProcessesRunning
}

function Confirm-SophosFilesExist
{
    $allFilesAndFoldersExist = $true
    if ((Confirm-FileOrFolderExists "C:\Program Files\Sophos") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\Program Files (x86)\Sophos") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\ProgramData\Sophos") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Sophos") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    return $allFilesAndFoldersExist
}

function Confirm-AbsoluteReady
{
    $isAbsoluteReady = $true

    if ((Confirm-AbsoluteProcessesRunning) -eq $false)
    {
        $isAbsoluteReady = $false
    }
    if ((Confirm-AbsoluteFilesExist) -eq $false)
    {
        $isAbsoluteReady = $false
    }
    
    if ($isAbsoluteReady)
    {
        Write-Host "Absolute is ready." -ForegroundColor Green
    }
    else
    {
        Write-Host "Found issue with Absolute." -ForegroundColor Red
    }
}

function Confirm-AbsoluteProcessesRunning
{
    $allProcessesRunning = $true
    if ((Confirm-ProcessRunning "rpcnet") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "Ctes") -eq $false)
    {
        $allProcessesRunning = $false
    }
    if ((Confirm-ProcessRunning "CtesHostSvc") -eq $false)
    {
        $allProcessesRunning = $false
    }
    return $allProcessesRunning
}

function Confirm-AbsoluteFilesExist
{
    $allFilesAndFoldersExist = $true
    if ((Confirm-FileOrFolderExists "C:\Windows\SysWOW64\rpcnet.exe") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\ProgramData\CTES") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\ProgramData\CTES\Ctes.exe") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    if ((Confirm-FileOrFolderExists "C:\ProgramData\CTES\logs") -eq $false)
    {
        $allFilesAndFoldersExist = $false
    }
    return $allFilesAndFoldersExist
}

function Confirm-TPMEnabled
{
    try
    {
        $tpmInfo = Get-TPM
    }
    catch
    {
        Write-Warning "Unable to obtain info about the TPM. Is session running as administrator?"
        return
    }    

    if ($null -eq $tpmInfo)
    {
        Write-Warning "Unable to obtain info about the TPM. Is session running as administrator?"
        return
    }
    
    if (($tpmInfo.TPMEnabled) -eq $true)
    {
        Write-Host "TPM is enabled." -ForegroundColor Green
    }
    else
    {
        Write-Host "TPM is NOT enabled." -ForegroundColor Red
    }
}

function Confirm-BitlockerEnabled
{
    $bitlockerInfo = Get-BitLockerVolume -MountPoint C -ErrorAction SilentlyContinue

    if ($null -eq $bitlockerInfo)
    {
        Write-Warning "Unable to get info about Bitlocker. Is session running as administrator?"
        return
    }

    if (($bitlockerInfo.VolumeStatus) -like "*EncryptionInProgress*")
    {
        Write-Host "Bitlocker encryption in progress." -ForegroundColor Green
    }
    elseif (($bitlockerInfo.VolumeStatus) -like "*FullyEncrypted*")
    {
        Write-Host "Bitlocker has encrypted the drive." -ForegroundColor Green
    }
    else
    {
        Write-Host "Bitlocker is NOT enabled." -ForegroundColor Red
    }
}

function Confirm-PageFileAutoManaged
{
    $isAutoManaged = Get-CimInstance Win32_ComputerSystem | Select-Object -ExpandProperty AutomaticManagedPageFile

    if ($null -eq $isAutoManaged) { return }

    if ($isAutoManaged)
    {
        Write-Host "Page file is auto-managed by system." -ForegroundColor Green
    }
    else
    {
        Write-Host "Page file is NOT auto-managed by system." -ForegroundColor Red
    }
}

function Confirm-UpdatesAvailable
{
    # Uses the Windows Update Agent API
    # https://learn.microsoft.com/en-us/windows/win32/api/_wua/
    # https://learn.microsoft.com/en-us/windows/win32/wua_sdk/searching--downloading--and-installing-updates
    # https://learn.microsoft.com/en-us/windows/win32/api/wuapi/nf-wuapi-iupdatesearcher-search

    Write-Host "Checking for updates..." -ForegroundColor "DarkCyan"
    $updateSession = New-Object -ComObject "Microsoft.Update.Session"
    $updateSearcher = $updateSession.CreateUpdateSearcher()
    $updates = $updateSearcher.Search("IsInstalled=0 and IsHidden=0").Updates 
    if ($updates.Count -gt 0)
    {
        Write-Host "Updates are available:" -ForegroundColor "Yellow"
        $updates | Select-Object -ExpandProperty "Title" | Write-Host -ForegroundColor "DarkCyan"

    }
    else
    {
        Write-Host "PC is up to date!" -ForegroundColor "Green"
    }
}

function Prompt-YesOrNo($question)
{
    Write-Host "$question`n[Y] Yes  [N] No"

    do
    {
        $response = Read-Host
        $validResponse = $response -imatch '^\s*[yn]\s*$' # regex matches y or n but allows spaces
        if (-not($validResponse)) 
        {
            Write-Warning "Please enter y or n."
        }
    }
    while (-not($validResponse))

    if ($response -imatch '^\s*y\s*$') # regex matches a y but allows spaces
    {
        return $true
    }
    return $false
}

# main
Test-SessionPrivileges
Show-TimeStamp
Confirm-WindowsVersionInfo
Confirm-BIOSVersionInfo
Show-UserProfiles
Confirm-DeviceNamedCorrectly
Confirm-JoinedToAzureAD
Confirm-FreshServiceReady
Confirm-SophosReady
Confirm-AbsoluteReady
Confirm-TPMEnabled
Confirm-BitlockerEnabled
Confirm-PageFileAutoManaged
$checkForUpdates = Prompt-YesOrNo "Would you like to check for updates?"
if ($checkForUpdates) { Confirm-UpdatesAvailable }
Read-Host "Press Enter to exit."