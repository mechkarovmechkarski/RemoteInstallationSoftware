<#
.SYNOPSIS
    The script has the following purposes:
    Installing .exe or .msi to destination computers in an OU at MS Windows Active Directory Domain.
    It supports creating certificates used for signing code and to encrypt/decrypt.
    It supports signing .ps1 files with a certificate.
    It supports encrypting Password with a certificate and save it to .txt file. It saves the username(unencrypted) in another .txt file.
    (Password can be decrypted only if you have the privete key of the certificate.)

.DESCRIPTION


.NOTES
    2020-05-06 Last modified
    Created by Nikola Velichkov
    nikola.velichkov@abv.bg
    
    Changes in version 0-07:
    *     

    Known bugs:
    *   No memory release is done when the program ends. The terminal that opened the script should be closed to release the memory.

    To do:
    ???     Create functions for Import and Export certificate, add it to button actions 
    *       Configure each computer to have it's own separate log file + the default program log file
    *3.     Create functionality to make additional remote commands before and after the installation
    *3.1    Create optional field to execute commands on remote computer before installation + checkbox to execute this commenads yes/no
    *3.2    Create optional field to execute commands on remote computer after installation + checkbox to execute this commenads yes/no
    *4.     Create new parameter from type string(which points to specific OU) and parameter from type file(which contains computers)
    *4.1    Create function to import computers as file to the parameter
    *4.2    Create function to export computers as file from AD OU
    *       Create GUI with import OU and text field to enter OU
    *       Create GUI to export computers list from AD OU as file
    *5.     Create field + option ONLY to run commands on computers by file or OU
    *       Find a way to check if program is already installed. Make a function that does it.
    *       Add progress bar showing the progress with the installation task.
    *       Add more documentation for the script.

    #Change font HOW-TO
    $labelLoading.Font = "Microsoft Sans Serif, 12pt, style=Bold"
#>



<#
    First prepare the log script and log file
#>
$serverName = $env:COMPUTERNAME

. "$PSScriptRoot\Modules\Function-Write-Log.ps1"
$logPath = "$PSScriptRoot\log.txt"
function logMessage {
    [CmdletBinding()]
    # Parameter help description
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Message,

        [Parameter(Mandatory = $true, Position = 2)]
        [ValidateSet("Error","Warn","Info")]
        [string]
        $logLevel,

        [Parameter(Mandatory = $false, Position = 3)]
        [string]
        $logPathNew = $logPath
    )
    
    Write-Log -Message $Message -Level $logLevel -Path $logPathNew
    $temp = Get-Item -Path $logPath | Get-Content -Tail 1
    try{
        if ($comboBox_logs.text -eq "Info") {
            $textBox_outbox.AppendText("$temp `r`n")
        } elseif (($comboBox_logs.text -eq "Warn") -and (($logLevel -eq "Warn") -or ($logLevel -eq "Error"))) {
            $textBox_outbox.AppendText("$temp `r`n")
        } elseif (($comboBox_logs.text -eq "Error") -and ($logLevel -eq "Error")) {
            $textBox_outbox.AppendText("$temp `r`n")
        } #End if
    } #End try
    catch{
    } #End catch
} #End function

<#
        Import all necessary modules and other file scripts
#>

logMessage -Message "Script starts initiating..." -logLevel Info
logMessage -Message "..." -logLevel Info
logMessage -Message "..." -logLevel Info
logMessage -Message "... the server name running the script is $serverName." -logLevel Info
logMessage -Message "Trying to import module for ActiveDirectory..." -logLevel Info
$temp
try{
    Import-Module activedirectory -ErrorAction Stop -ErrorVariable temp -WarningAction SilentlyContinue -WarningVariable temp
    logMessage -Message "... $temp" -logLevel Info
} #End try
catch{
    $temp = $PSItem.Exception.Message
    logMessage -Message "$temp" -logLevel Error
    $temp = $PSItem.Exception.GetType().fullname
    logMessage -Message "Exception type is: $temp" -logLevel Info
    $temp = $PSItem.ScriptStackTrace
    logMessage -Message "Exception trace: $temp" -logLevel Info
} #End catch

#Import function which checks if reboot is required
. "$PSScriptRoot\Modules\Function-Get-PendingReboot.ps1"


<#

        Initialize all functions

#>
function InitialValues {
    param(
        [CmdletBinding()]
        [Parameter(Mandatory = $true, Position=0,
        HelpMessage = "Write the shared folder the content of which you wish to copy, without '\\SERVER', and starting with '\'")]
        [ValidateScript( {Test-Path -Path "\\$env:computername$_" } )]
        [string]
        $serverSharedFolder,

        [Parameter(Mandatory = $true, Position=1,
        HelpMessage = "Please write the path that point to the .exe or .msi, after you have entered in the SharedFolder you previusly typed. Start with '.\'")]
        [ValidateScript( {Test-Path -Path "\\$env:computername$serverSharedFolder\$_" })]
        [string]
        $instFile,

        [Parameter(Mandatory=$true, Position=2,
        HelpMessage = "Enter the service account common or sAMAccountName, i.e. ServiceAccount WITHOUT the domain suffix. This should be Administrator account.")]
        [ValidateScript({$_ -notmatch "[\@]+[\w+|\d+|\.]+"})]
        [string]
        $svcAccountName,

        [Parameter(Mandatory = $true, Position=3,
        HelpMessage = "Write where the password and username files are stored - local or network location. Do this in the format 'C:\temp' or '\\server-01\shared' ")]
        [ValidateScript( {Test-Path -Path $_ })]
        [string]
        $svcSharedPath,

        [Parameter(Mandatory = $false, Position=4,
        HelpMessage = "Enter yes/no (default is 'no') if initial reboot check is required before we install the application. If reboot is required the installation will stop.")]
        [ValidateSet('Yes','No')]
        [string]
        $initialRebootRequired = "No",

        [Parameter(Mandatory = $true, Position=5,
        HelpMessage = 'This should be passed as a list in the format <! "one","two","three" !>')]
        [System.Collections.ArrayList]
        $EXEArguments,

        [Parameter(Mandatory = $true, Position=6,
        HelpMessage = "Enter full path where you would like to copy the file.")]
        [string]
        $localPath,

        [Parameter(Mandatory = $true, Position=7,
        HelpMessage = "Enter file with computers, to which you wish to push the installation.")]
        [string]
        $ADComputers
    )
} #End function

function Get-SvcAccountCredential
    #This function will Retrieve the Encrypted Password and then Decrypt it!
{
    [CmdletBinding()]
    [OutputType([string])]
    # Retrieve the installed certificate
    $ImportedCert = Get-ChildItem cert:\currentuser\my | Where-Object {$_.Subject -match "$($svcAccountName+'-SelfSignedPSScriptCipherCert')"}
    logMessage -Message "The certificate is imported successfully from the certificate store. " -logLevel Info
    # Convert certificate subject to cn= format.
    $certCn =  "cn=$($svcAccountName+'-SelfSignedPSScriptCipherCert')"
    logMessage -Message "Trying open the file $pwFilePath" -logLevel Info
    $EncryptedPwd = Get-Content -Path $pwFilePath
    logMessage -Message "File $pwFilePath is opened successfully." -logLevel Info
    # Decrypt password
    $DecryptedPwd = $EncryptedPwd | Unprotect-CmsMessage -To $certCn
    return $DecryptedPwd
} #End function

function SoftwareInstallation ([String[]]$computerNames) {
    [CmdletBinding()]
    <#      
        Set destination drive and folder

        This should be something like:
        $destDrive = "C:"
        $destFolder = "\install"
    #>
    $destDrive = $localPath.Substring(0,2)
    $destFolder = $localPath.Substring(2)
    $destFolderPath = $destDrive+$destFolder
    logMessage -Message "The folder to which the installation files will be copied on each machine is $destFolderPath" -logLevel Info

    #Set install file used later in installation
    $instFile = $instFile.Substring(1,$instFile.Length)
    $instFilePath = $destFolderPath+$instFile
    logMessage -Message "The installation file will be located on $instFilePath" -logLevel Info

    logMessage -Message "All preparations are made. Initiate connections to each computer from the list." -logLevel Info
    #Iterate over each computer in the list of computers
    foreach ($computerName in $computerNames) {
        #Some computers may go offline before starting installation or during the installation. So we use Try statement.
        Try {
            #Set parameters and enter PowerShell Session
            $PSSessionParameters = @{
                ComputerName = $computerName
                Authentication = "Kerberos"
                Credential = $Cred
            }
            logMessage -Message "Initiate PSSession to $ComputerName ." -logLevel Info
            $s1 = New-PSSession @PSSessionParameters
            logMessage -Message "Connection with computer $ComputerName is established successfully." -logLevel Info

            #Create and map PSDrive
            $PSDriveParameters = @{
                Name = "temp"
                PSProvider = "FileSystem"
                Root = "\\$serverName$serverSharedFolder"
                Credential = $Cred
            }
            $mappedFolderPath = $PSDriveParameters.Root
            logMessage -Message "On $ComputerName : Trying to map the folder $mappedFolderPath as a drive..." -logLevel Info
            Invoke-Command -Session $s1 -ScriptBlock {New-PSDrive @using:PSDriveParameters} -AsJob | Wait-Job
            logMessage -Message "On $ComputerName : Folder is mapped successfully." -logLevel Info
            logMessage -Message "On $ComputerName : The mapped folder is $mappedFolderPath" -logLevel Info

            #Copy installation data
            logMessage -Message "On $ComputerName : The folder $destFolderPath will be created if it does not exist. " -logLevel Info
            Invoke-Command -Session $s1 -ScriptBlock {New-Item -Path $using:destFolderPath -ItemType Directory -Force} -AsJob | Wait-Job
            logMessage -Message "On $ComputerName : The folder is created or already exist." -logLevel Info
            logMessage -Message "On $ComputerName : Files on $mappedFolderPath begin to copy on $destFolderPath" -logLevel Info
            Invoke-Command -Session $s1 -ScriptBlock {Copy-Item -Path $using:mappedFolderPath\* -Destination $using:destfolderPath -Credential $Cred -Recurse} -AsJob | Wait-Job
            logMessage -Message "On $ComputerName : The copy operation has finished successfully." -logLevel Info

            #Remove the PSDrive
            logMessage -Message "On $ComputerName : Preparing to remove the drive on which is mapped folder $mappedFolderPath." -logLevel Info
            Invoke-Command -Session $s1 -ScriptBlock {Remove-PSDrive $using:PSDriveParameters.Name} -AsJob | Wait-Job
            logMessage -Message "On $ComputerName : The drive is removed successfully." -logLevel Info

            #Add aditional commands before installation


            #Start installation
            <#
            $EXEArguments = @(
                "/S"
                "/v/qn"
            )
            #>
            logMessage -Message "On $ComputerName : Starting installation." -logLevel Info
            Invoke-Command -Session $s1 -ScriptBlock {Start-Process $using:instFilePath -ArgumentList $using:EXEArguments -Wait} -AsJob | Wait-Job
            logMessage -Message "On $ComputerName : Installation has completed." -logLevel Info

            #Add aditional command after installation
            Invoke-Command -Session $s1 -ScriptBlock {Start-Process 'C:\Program Files (x86)\ManageSoft\Tracker\Ndtrack.exe' -ArgumentList '/t $using:computerName' -Wait} -AsJob | Wait-Job
            
            #Close PowerShell Session, for security reasons
            logMessage -Message "Preparing to stop the connection with $ComputerName ." -logLevel Info
            Remove-PSSession -Session $s1
            logMessage -Message "Connection with computer $ComputerName has ended successfully." -logLevel Info
        } #End try
        #Catch all computers that have gone offline before installation or during it + other errors
        Catch {
            logMessage -Message "Connection has broken or not established at all." -logLevel Warn
            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Warn
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Warn
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Warn
        } #End catch
    } #End foreach
} #End function

function CheckInstallation ([String[]]$OrganizationUnit) {
    [CmdletBinding()]
    [hashtable]$list = @{}
    #Create empty list and fill it with all computers that are unavailable
    $UnavailableComputers = New-Object Collections.Generic.List[String]
    #Create empty list and fill it with all computers that don't have the software installed
    $AvailableComputers = New-Object Collections.Generic.List[String]

    foreach($computerName in $OrganizationUnit) {
        #try to see if the computer is online
        Try {
            #Set parameters and enter PowerShell Session
            $PSSessionParameters = @{
                ComputerName = $computerName
                Authentication = "Kerberos"
                Credential = $Cred
            }
            $s1 = New-PSSession @PSSessionParameters  
            
            #Check software installation and write computers that don't have the software in a list
            $tempBoolean = Invoke-Command -Session $s1 -ScriptBlock {Test-Path 'C:\Program Files (x86)\ManageSoft'} -AsJob | Wait-Job
            if ($tempBoolean){
                $AvailableComputers.Add($computerName)
            } else {Continue}
            
            #Close PowerShell Session, for security reasons
            Remove-PSSession -Session $s1
        }
        #if the computer is not online write it to the list
        Catch {
            $UnavailableComputers.Add($computerName)

            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        }
    }

    #Write those lists (as values) to the hashtable with some key, so you can call the lists
    #Explaination!!!We have two keys in out hashtable. So each key points to a list of strings!!!
    $list.UnavailableComputers = $UnavailableComputers
    $list.AvailableComputers = $AvailableComputers
    #Return list with all computers that don't have the software installed or are unavailable
    return $list
} #End function

function processComputers {
    [CmdletBinding()]
    ########Collect computers lists#######
    #Get all unencrypted notebooks
    #$computersUnencrypted = (Get-ADComputer -Filter * -SearchBase "OU=Mobile Computers, OU=Computers, OU=Company, DC=domain, DC=local").Name
    #$list1 = CheckInstallation -OrganizationUnit $computersUnencrypted
    #SoftwareInstallation -computerName $list1.AvailableComputers

    #Get all encrypted notebooks
    $computersEncrypted = [string[]](Get-ADComputer -Filter * -SearchBase "OU=Computers, OU=Home, OU=Domain Controllers, DC=home, DC=local").Name
    $list2 = CheckInstallation -OrganizationUnit $computersEncrypted
    SoftwareInstallation -computerName $list2.AvailableComputers

    #Get all workstations
    #$computersWorkstations = (Get-ADComputer -Filter * -SearchBase "OU=Workstations, OU=Computers, OU=Company, DC=domain, DC=local").Name
    #$list3 = CheckInstallation -OrganizationUnit $computersWorkstations
    #SoftwareInstallation -computerName $list3.AvailableComputers

    #Add-Content Unavailable-Computers.txt $computer
    if([adsi]::Exists("LDAP://$ADComputers")){
        $computers = [string[]](Get-ADComputer -Filter * -SearchBase $ADComputers).Name
    } else {
        
    }
    
} #End function

function CreateCredObj {
    [CmdletBinding()]
    
    #Account credentials files 
    $upnFilePath = "$svcSharedPath\$svcAccountName-upn.txt"
    $pwFilePath = "$svcSharedPath\$svcAccountName-pw.txt"

    logMessage -Message "Start preparing credential object." -logLevel Info
    logMessage -Message "Extracting credentials." -logLevel Info
    $svcAccountUpn = Get-Content -Path $upnFilePath
    $svcAccountPassword = Get-SvcAccountCredential
    $SecurePwd = $svcAccountPassword | ConvertTo-SecureString -AsPlainText -Force
    logMessage -Message "Extracting successful. Cleaning up..." -logLevel Info
    $svcAccountPassword = ""
    logMessage -Message "Clean up completed." -logLevel Info

    #Prepare the Credential object
    logMessage -Message "Creating secure credential object." -logLevel Info
    $Cred = New-Object System.Management.Automation.PSCredential ($svcAccountUpn, $SecurePwd)
    logMessage -Message "Secure credential object is created successfully." -logLevel Info
} #End function

function CreateEncryptDecryptSelfSignedCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $svcAccountName,

        [Parameter(Mandatory = $true, Position = 2)]
        [int]
        $Months
    )

    New-SelfSignedCertificate -KeyDescription "PowerShell Script Encryption-Decryption Key" `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -KeyFriendlyName "SelfSignedPSScriptEncryptDecryptKey" `
    -FriendlyName "$svcAccountName-SelfSignedPSScriptCipherCert" `
    -Subject "$svcAccountName-SelfSignedPSScriptCipherCert" `
    -KeyUsage "DataEncipherment" `
    -Type "DocumentEncryptionCert" `
    -HashAlgorithm "sha256" `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -NotAfter (Get-Date).AddMonths($Months)

    logMessage -Message "The self-signed certificate for Encrypt/Decrypt purposes is created successfully." -logLevel Info
    logMessage -Message "The certificate Subject name is $svcAccountName-SelfSignedPSScriptCipherCert and will be valid $Months months." -logLevel Info
} #End function

function CreateCodeSigningSelfSignedCertificate {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $svcAccountName,

        [Parameter(Mandatory = $true, Position = 2)]
        [int]
        $Months
    )

    New-SelfSignedCertificate -CertStoreLocation cert:\currentuser\my `
    -Subject "$svcAccountName-SelfSignedCodeSigningCert" `
    -FriendlyName "$svcAccountName-SelfSignedCodeSigningCert" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider" `
    -KeyExportPolicy Exportable `
    -KeyUsage DigitalSignature `
    -Type CodeSigningCert `
    -NotAfter (Get-Date).AddMonths($Months)

    logMessage -Message "The self-signed certificate for Code signing purposes is created successfully." -logLevel Info
    logMessage -Message "The certificate Subject name is $svcAccountName-SelfSignedCodeSigningCert and will be valid $Months months." -logLevel Info
} #End function

function EncryptAccountCredentials {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $svcAccountName,

        [Parameter(Mandatory = $true, Position = 3)]
        [string]
        $SaveFilePath
    )
    #$svcAccountName = Read-Host "Write what will be the service account using this certificate"
    #$svcDomain = Read-Host "Write what will be the domain for this account"
    

    logMessage -Message "Trying to import the certificate $svcAccountName-SelfSignedPSScriptCipherCert" -logLevel Info
    $ImportedCert = Get-ChildItem cert:\currentuser\my | Where-Object {$_.Subject -match "$svcAccountName-SelfSignedPSScriptCipherCert"} 
    if ($null -eq $ImportedCert) {
        logMessage -Message "Import unsuccessful. The certificate does not exist" -logLevel Info
        return $false
    } else {
        logMessage -Message "Import successful." -logLevel Info
    } #End if

    logMessage -Message "Requesting the service account password. (It will be encrypted)" -logLevel Info
    $cred = Get-Credential -Message "Enter the service account password that will be used to execute scripts." -UserName "$svcAccountName@domain"
    logMessage -Message "Credentials collected." -logLevel Info
    $svcAccountUpn = $cred.UserName

    logMessage -Message "Converting the certificate subject to CN format." -logLevel Info
    $certCn = "cn=$($svcAccountName+'-SelfSignedPSScriptCipherCert')"

    #$SaveFilePath = Read-Host "Write where will be stored the password and username files in the format C:\temp or \\server-01\shared"
    logMessage -Message "Creating files on $SaveFilePath" -logLevel Info
    $upnFilePath = "$SaveFilePath$svcAccountName-upn.txt"
    $pwFilePath = "$SaveFilePath$svcAccountName-pw.txt"
    logMessage -Message "Username file created $upnFilePath" -logLevel Info
    logMessage -Message "Password file created $pwFilePath" -logLevel Info

    $svcAccountUsername = $cred.GetNetworkCredential().Username 
    $svcAccountPassword = $cred.GetNetworkCredential().Password 

    logMessage -Message "Encrypting service account password with the certificate." -logLevel Info
    $EncryptedPwd = $svcAccountPassword | Protect-CmsMessage -To $certCn
    
    # Write service account username to UPN file
    logMessage -Message "Exporting service account username to $upnFilePath." -logLevel Info
    Set-Content -Path $upnFilePath -Value $svcAccountUpn -Force -Verbose
    logMessage -Message "Data is exported to the file successfully." -logLevel Info
    
    # Write encrypted password to shared password file
    logMessage -Message "Exporting service account encrypted password for $svcAccountName to $pwFilePath." -logLevel Info
    Set-Content -Path $pwFilePath -Value $EncryptedPwd -Force -Verbose
    logMessage -Message "Data is exported to the file successfully." -logLevel Info
    
    # Show username
    logMessage -Message "Showing data in $upnFilePath" -logLevel Info
    $temp = Get-Content -Path $upnFilePath -Verbose
    logMessage -Message "$temp" -logLevel Info
    
    # Show encrypted password
    logMessage -Message "Showing data in $pwFilePath" -logLevel Info
    $temp = Get-Content -Path $pwFilePath -Verbose
    logMessage -Message "$temp" -logLevel Info

    #clear data from variable
    $temp = ""

    return $true
} #End function

function SignPSScripts {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory = $true, Position = 1)]
        [string]
        $svcAccountName,

        [Parameter(Mandatory = $true, Position = 2)]
        [string]
        $filesPath
    )

    logMessage -Message "Trying to import the certificate $svcAccountName-SelfSignedCodeSigningCert ." -logLevel Info
    $ImportedCert = Get-ChildItem cert:\currentuser\my | Where-Object {$_.Subject -match "$svcAccountName-SelfSignedCodeSigningCert"}
    if ($null -eq $ImportedCert){
        logMessage -Message "Import unsuccessful. The certificate does not exist." -logLevel Info
        return $false
    } else {
        $temp = $ImportedCert.subject
        logMessage -Message "Import successful. The certificate is $temp" -logLevel Info
    } #End if
    
    $PSscripts = Get-ChildItem -Path $filesPath -Filter "*.ps1" -Recurse | Select-Object FullName
    logMessage -Message "Start signing powershell files ..." -logLevel Info
    foreach ($script in $PSscripts){
        $file = $script[0].FullName
        logMessage -Message "Preparing to sign $file ." -logLevel Info
        Set-AuthentiCodeSignature $file $ImportedCert
        logMessage -Message "$file is signed successfully." -logLevel Info
    } #End foreach

    return $true
} #End function

<#
#Create the credential object
CreateCredObj

#Run the Installation Check and the Installation itself
processComputers
#>


<#
    Other function specific for the GUI
#>
function HelpFormNull {
    #This function will clean all text
    $label_summary_HelpForm_1.Text = ""
    $label_summary_HelpForm_2.Text = ""
    $label_summary_HelpForm_3.Text = ""
    $label_summary_HelpForm_4.Text = ""
    $label_summary_HelpForm_5.Text = ""
    $label_summary_HelpForm_6.Text = ""
}

<#
        Create the GUI form.
        Then fill with GUI objects and data.
        And last Run the form.
#>

Add-Type -assembly System.Windows.Forms
Add-Type -Assembly System.Drawing
[Windows.Forms.Application]::EnableVisualStyles()

<#
    Public variables used in GUI
#>
$buttonSize_1 = New-Object System.Drawing.Size(120,20)
$buttonSize_2 = New-Object System.Drawing.Size(240,20)
$buttonSize_3 = New-Object System.Drawing.Size(80,20)

$main_form = New-Object System.Windows.Forms.Form
$main_form.Text ='Install Apllication GUI'
$main_form.Width = 1280
$main_form.Height = 740
$main_form.AutoSize = $true
$main_form.StartPosition = "CenterScreen"

$Button_main_Form_Exit = New-Object System.Windows.Forms.Button
$Button_main_Form_Exit.Text = "Exit program"
$Button_main_Form_Exit.Location = New-Object System.Drawing.Point(1180,1)
$Button_main_Form_Exit.Size = $buttonSize_3
$Button_main_Form_Exit.Add_Click(
    {
        $main_form.Close()
    }
)
$main_form.Controls.Add($Button_main_Form_Exit)

<#

    GUI - Left part of the GUI application
    Creating Labels

#>
$label_ServerSharedFolder = New-Object System.Windows.Forms.Label
$label_ServerSharedFolder.Text = "Shared folder - full path"
$label_ServerSharedFolder.Location  = New-Object System.Drawing.Point(0,10)
$label_ServerSharedFolder.AutoSize = $true
$main_form.Controls.Add($label_ServerSharedFolder)

$label_instFile = New-Object System.Windows.Forms.Label
$label_instFile.Text = "Install file"
$label_instFile.Location = New-Object System.Drawing.Point(0,30)
$label_instFile.AutoSize = $true
$main_form.Controls.Add($label_instFile)

$label_svcAccountName = New-Object System.Windows.Forms.Label
$label_svcAccountName.Text = "Admin service account"
$label_svcAccountName.Location = New-Object System.Drawing.Point(0,50)
$label_svcAccountName.AutoSize = $true 
$main_form.Controls.Add($label_svcAccountName)

$label_svcSharedPath = New-Object System.Windows.Forms.Label
$label_svcSharedPath.Text = "Account credentials location"
$label_svcSharedPath.Location = New-Object System.Drawing.Point(0,70)
$label_svcSharedPath.AutoSize =$true
$main_form.Controls.Add($label_svcSharedPath)

$label_initialRebootRequired = New-Object System.Windows.Forms.Label
$label_initialRebootRequired.Text = "Do you want to skip computers that requires reboot?"
$label_initialRebootRequired.Location = New-Object System.Drawing.Point(0,90)
$label_initialRebootRequired.AutoSize = $true 
$main_form.Controls.Add($label_initialRebootRequired)

$label_EXEArguments = New-Object System.Windows.Forms.Label
$label_EXEArguments.Text = "Enter EXE arguments"
$label_EXEArguments.Location = New-Object System.Drawing.Point(0,110)
$label_EXEArguments.AutoSize = $true 
$main_form.Controls.Add($label_EXEArguments)

$label_localPath = New-Object System.Windows.Forms.Label
$label_localPath.Text = "Local folder on remote computers - full path"
$label_localPath.Location = New-Object System.Drawing.Point(0,130)
$label_localPath.AutoSize = $true 
$main_form.Controls.Add($label_localPath)

$label_Computers = New-Object System.Windows.Forms.Label
$label_Computers.Text = "Enter AD OU path or enter .txt file path which contains a list of computers"
$label_Computers.Location = New-Object System.Drawing.Point(80,170)
$label_Computers.Autosize = $true
$main_form.Controls.Add($label_Computers)


<#

    Add textbox field next to the labels

#>
$textBox_ServerSharedFolder = New-Object System.Windows.Forms.TextBox
$textBox_ServerSharedFolder.Location = New-Object System.Drawing.Point(160,10)
$textBox_ServerSharedFolder.Width = 400
$textBox_ServerSharedFolder.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_ServerSharedFolder.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_ServerSharedFolder)

$textBox_instFile = New-Object System.Windows.Forms.TextBox
$textBox_instFile.Location = New-Object System.Drawing.Point(160,30)
$textBox_instFile.Width = 180 
$textBox_instFile.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_instFile.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_instFile)

$textBox_svcAccountName = New-Object System.Windows.Forms.TextBox
$textBox_svcAccountName.Location = New-Object System.Drawing.Point(160,50)
$textBox_svcAccountName.Width = 180
$textBox_svcAccountName.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_svcAccountName.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_svcAccountName)

$textBox_svcSharedPath = New-Object System.Windows.Forms.TextBox
$textBox_svcSharedPath.Location = New-Object System.Drawing.Point(160,70)
$textBox_svcSharedPath.Width = 400
$textBox_svcSharedPath.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_svcSharedPath.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_svcSharedPath)

$ComboBox_initialRebootRequired = New-Object System.Windows.Forms.ComboBox
$ComboBox_initialRebootRequired.Width = 60
$ComboBox_initialRebootRequired.Items.Add("Yes")
$ComboBox_initialRebootRequired.Items.Add("No")
$ComboBox_initialRebootRequired.SelectedIndex = 1
$ComboBox_initialRebootRequired.DropDownStyle = 2
$ComboBox_initialRebootRequired.Location = New-Object System.Drawing.Point(270,90)
$main_form.Controls.Add($ComboBox_initialRebootRequired)

$textBox_EXEArguments = New-Object System.Windows.Forms.TextBox
$textBox_EXEArguments.Location = New-Object System.Drawing.Point(160,110)
$textBox_EXEArguments.Width = 180
$textBox_EXEArguments.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_EXEArguments.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_EXEArguments)

$textBox_localPath = New-Object System.Windows.Forms.TextBox
$textBox_localPath.Location = New-Object System.Drawing.Point(240,130)
$textBox_localPath.Width = 320 
$textBox_localPath.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_localPath.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_localPath)

$ComboBox_Computers = New-Object System.Windows.Forms.ComboBox
$ComboBox_Computers.Width = 80
$ComboBox_Computers.Items.Add("OU path")
$ComboBox_Computers.Items.Add("File path")
$ComboBox_Computers.DropDownStyle = 2
$ComboBox_Computers.Location = New-Object System.Drawing.Point(0,190)
$ComboBox_Computers.Autosize = $true
$main_form.Controls.Add($ComboBox_Computers)

$textBox_Computers = New-Object System.Windows.Forms.TextBox
$textBox_Computers.Location = New-Object System.Drawing.Point(160,190)
$textBox_Computers.Width = 400
$textBox_Computers.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_Computers.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_Computers)

<#

    Create label next to textBoxes

#>
$label_ServerSharedFolder_1 = New-Object System.Windows.Forms.Label
$label_ServerSharedFolder_1.Text = ""
$label_ServerSharedFolder_1.Location = New-Object System.Drawing.Point(700,10)
$label_ServerSharedFolder_1.AutoSize = $true
$main_form.Controls.Add($label_ServerSharedFolder_1)

$label_instFile_1 = New-Object System.Windows.Forms.Label
$label_instFile_1.Text = ""
$label_instFile_1.Location = New-Object System.Drawing.Point(700,30)
$label_instFile_1.AutoSize = $true 
$main_form.Controls.Add($label_instFile_1)

$label_svcAccountName_1 = New-Object System.Windows.Forms.Label
$label_svcAccountName_1.Text = ""
$label_svcAccountName_1.Location = New-Object System.Drawing.Point(700,50)
$label_svcAccountName_1.AutoSize = $true 
$main_form.Controls.Add($label_svcAccountName_1)

$label_svcSharedPath_1 = New-Object System.Windows.Forms.Label
$label_svcSharedPath_1.Text = ""
$label_svcSharedPath_1.Location = New-Object System.Drawing.Point(700,70)
$label_svcSharedPath_1.AutoSize = $true
$main_form.Controls.Add($label_svcSharedPath_1)

$label_svcSharedPath_2 = New-Object System.Windows.Forms.Label
$label_svcSharedPath_2.Text = ""
$label_svcSharedPath_2.Location = New-Object System.Drawing.Point(700,90)
$label_svcSharedPath_2.AutoSize = $true
$main_form.Controls.Add($label_svcSharedPath_2)

$label_initialRebootRequired_1 = New-Object System.Windows.Forms.Label
$label_initialRebootRequired_1.Text = "Optional"
$label_initialRebootRequired_1.ForeColor = "blue"
$label_initialRebootRequired_1.Location = New-Object System.Drawing.Point(330,90)
$label_initialRebootRequired_1.AutoSize = $true 
$main_form.Controls.Add($label_initialRebootRequired_1)

$label_EXEArguments_1 = New-Object System.Windows.Forms.Label
$label_EXEArguments_1.Text = ""
$label_EXEArguments_1.Location = New-Object System.Drawing.Point(700,110)
$label_EXEArguments_1.AutoSize = $true
$main_form.Controls.Add($label_EXEArguments_1)

$label_Computers1 = New-Object System.Windows.Forms.Label
$label_Computers1.Text = ""
$label_Computers1.Location = New-Object System.Drawing.Point(700,170)
$label_Computers1.AutoSize = $true 
$main_form.Controls.Add($label_Computers1)


<#

    Create Check buttons

#>
$Button_ServerSharedFolder = New-Object System.Windows.Forms.Button
$Button_ServerSharedFolder.Text = "Check"
$Button_ServerSharedFolder.Location = New-Object System.Drawing.Point(570,10)
$Button_ServerSharedFolder.Size = $buttonSize_1
$Button_ServerSharedFolder.Add_Click(
    {
        logMessage -Message "Checking server shared folder path..." -logLevel Info
        if( -not ([string]::IsNullOrEmpty($textBox_ServerSharedFolder.Text)) -and (Test-Path -Path $textBox_ServerSharedFolder.Text -ErrorAction SilentlyContinue)){
            $label_ServerSharedFolder_1.ForeColor = "green"
            $label_ServerSharedFolder_1.Text = "Path exists."
            logMessage -Message $label_ServerSharedFolder_1.Text -logLevel Info
        } else {
            $label_ServerSharedFolder_1.ForeColor = "red"
            $label_ServerSharedFolder_1.Text = "Path does not exist."
            logMessage -Message $label_ServerSharedFolder_1.Text -logLevel Info
        } #End if
    } #End button action
) #End button
$main_form.Controls.Add($Button_ServerSharedFolder)

$Button_instFile = New-Object System.Windows.Forms.Button
$Button_instFile.Text = "Check"
$Button_instFile.Location = New-Object System.Drawing.Point(570,30)
$Button_instFile.Size = $buttonSize_1
$Button_instFile.Add_Click(
    {
        logMessage -Message "Checking file existance..." -logLevel Info
        logMessage -Message "Checking file type .exe or .msi..." -logLevel Info
        try{
            $temp = $textBox_ServerSharedFolder.Text+$textBox_instFile.Text.Substring(1,$textBox_instFile.Text.Length-1)
            if( -not ([string]::IsNullOrEmpty($textBox_instFile.Text)) -and (Test-Path -Path $temp -PathType Leaf)){
                $label_instFile_1.ForeColor = "green"
                $label_instFile_1.Text = "File exists."
                logMessage -Message $label_instFile_1.Text -logLevel Info
            } else {
                $label_instFile_1.ForeColor = "red"
                $label_instFile_1.Text = "File does not exist."
                logMessage -Message $label_instFile_1.Text -logLevel Info
            } #End if
        } #End try
        catch [ArgumentOutOfRangeException]{
            $label_instFile_1.ForeColor = "red"
            $label_instFile_1.Text = "File does not exist."
            logMessage -Message $label_instFile_1.Text -logLevel Info
        } #End catch
        catch {
            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        } #End catch
    } #End button action
) #End button
$main_form.Controls.Add($Button_instFile)

$Button_svcAccountName = New-Object System.Windows.Forms.Button
$Button_svcAccountName.Text = "Check"
$Button_svcAccountName.Location = New-Object System.Drawing.Point(570,50)
$Button_svcAccountName.Size = $buttonSize_1
$Button_svcAccountName.Add_Click(
    {
        logMessage -Message "Checking user existance in Active Directory..." -logLevel Info
        try {
            Get-ADUser -Identity $textBox_svcAccountName.Text
            $label_svcAccountName_1.ForeColor = "green"
            $label_svcAccountName_1.Text = "User exists."
            logMessage -Message $label_svcAccountName_1.Text -logLevel Info
        } #End catch
        catch [Microsoft.ActiveDirectory.Management.ADIdentityResolutionException] {
            $label_svcAccountName_1.ForeColor = "red"
            $label_svcAccountName_1.Text = "User does not exist."
            logMessage -Message $label_svcAccountName_1.Text -logLevel Info
        } #End catch
        catch [System.Management.Automation.ParameterBindingException] {
            $label_svcAccountName_1.ForeColor = "red"
            $label_svcAccountName_1.Text = "No data."
            logMessage -Message $label_svcAccountName_1.Text -logLevel Info
        } #End catch
        catch {
            $label_svcAccountName_1.ForeColor = "red"
            $label_svcAccountName_1.Text = "Check logs."

            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        } #End catch
    } #End button action
) #End button
$main_form.Controls.Add($Button_svcAccountName)

$Button_svcSharedPath = New-Object System.Windows.Forms.Button
$Button_svcSharedPath.Text = "Check"
$Button_svcSharedPath.Location = New-Object System.Drawing.Point(570,70)
$Button_svcSharedPath.Size = $buttonSize_1
$Button_svcSharedPath.Add_Click(
    {
        logMessage -Message "Checking credentials folder path..." -logLevel Info
        if( -not ([string]::IsNullOrEmpty($textBox_svcSharedPath.Text)) -and (Test-Path -Path $textBox_svcSharedPath.Text -ErrorAction SilentlyContinue)){
            $label_svcSharedPath_1.ForeColor = "green"
            $label_svcSharedPath_1.Text = "Path exists."
            logMessage -Message $label_svcSharedPath_1.Text -logLevel Info
        } else {
            $label_svcSharedPath_1.ForeColor = "red"
            $label_svcSharedPath_1.Text = "Path does not exist."
            logMessage -Message $label_svcSharedPath_1.Text -logLevel Info
        } #End if

        logMessage -Message "Checking credential files existance..." -logLevel Info
        $temp = $textBox_svcSharedPath.Text+"\"+$textBox_svcAccountName.Text+"-upn.txt"
        $temp1 = $textBox_svcSharedPath.Text+"\"+$textBox_svcAccountName.Text+"-pw.txt"
        if((Test-Path -Path $temp -PathType Leaf) -and (Test-Path -Path $temp1 -PathType Leaf)){
            $label_svcSharedPath_2.ForeColor = "green"
            $label_svcSharedPath_2.Text = "Files exists."
            logMessage -Message $label_svcSharedPath_2.Text -logLevel Info
        } else {
            $label_svcSharedPath_2.ForeColor = "red"
            $label_svcSharedPath_2.Text = "Files does not exist."
            logMessage -Message $label_svcSharedPath_2.Text -logLevel Info
        } #End if
    } #End button action
) #End button
$main_form.Controls.Add($Button_svcSharedPath)

$Button_initialRebootRequired = New-Object System.Windows.Forms.Button
$Button_initialRebootRequired.Text = "Check if $serverName requires reboot"
$Button_initialRebootRequired.Location = New-Object System.Drawing.Point(450,90)
$Button_initialRebootRequired.Size = $buttonSize_2
$Button_initialRebootRequired.Add_Click(
    {
        Get-PendingReboot -ComputerName $serverName -ErrorLog $logPath
    } #End button action
) #End button
$main_form.Controls.Add($Button_initialRebootRequired)

$Button_EXEArguments = New-Object System.Windows.Forms.Button
$Button_EXEArguments.Text = "Check"
$Button_EXEArguments.Location = New-Object System.Drawing.Point(570,110)
$Button_EXEArguments.Size = $buttonSize_1
$Button_EXEArguments.Add_Click(
    {    
        logMessage -Message "Checking arguments..." -logLevel Info
        try {
            $temp = @()
            $temp = $textBox_EXEArguments.Text.Split(" ")
            
            $temp1 = $true
            foreach ($item in $temp){
                if ("-" -ne $item.Substring(0,1)){
                    $temp1 = $false
                    logMessage -Message "Argument $item is incorrect" -logLevel Info
                } #End if
            } #End foreach
            logMessage -Message "... complete." -logLevel Info

            if($temp1){
                $label_EXEArguments_1.ForeColor = "green"
                $label_EXEArguments_1.Text = "Data is OK."
                logMessage -Message $label_EXEArguments_1.Text -logLevel Info
            } else{
                $label_EXEArguments_1.ForeColor = "red"
                $label_EXEArguments_1.Text = "Incorrect data."
                logMessage -Message $label_EXEArguments_1.Text -logLevel Info
            } #End if
        } #End try
        catch [System.Management.Automation.MethodInvocationException]{
            $label_EXEArguments_1.ForeColor = "red"
            $label_EXEArguments_1.Text = "No data"
            logMessage -Message "No data." -logLevel Info
        } #End catch
        catch {
            $label_EXEArguments_1.ForeColor = "red"
            $label_EXEArguments_1.Text = "Check logs."

            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        } #End catch
    } #End button action
) #End button
$main_form.Controls.Add($Button_EXEArguments)

$Button_Computers = New-Object System.Windows.Forms.Button
$Button_Computers.Text = "Check"
$Button_Computers.Location = New-Object System.Drawing.Point(570,170)
$Button_Computers.Size = $buttonSize_1
$Button_Computers.Add_Click(
    {
        if ($ComboBox_Computers.SelectedIndex -eq 0) {
            try {
                logMessage -Message "Checking the format of the OU..." -logLevel Info
                $temp = $textBox_computers.Text
                $OUExist = [adsi]::Exists("LDAP://$temp")
                logMessage -Message "Format is OK." -logLevel Info
            } #End try
            catch {
                $label_Computers1.ForeColor = "red"
                $label_Computers1.Text = "Check logs."

                $temp = $PSItem.Exception.Message
                logMessage -Message "$temp" -logLevel Error
                $temp = $PSItem.Exception.GetType().fullname
                logMessage -Message "Exception type is: $temp" -logLevel Info
                $temp = $PSItem.ScriptStackTrace
                logMessage -Message "Exception trace: $temp" -logLevel Info
            } #End catch

            if (-not $OUExist) {
                logMessage -Message "Checking if OU path exist..." -logLevel Info
                logMessage -Message "Supplied path does not exist." -logLevel Info

                $label_Computers1.ForeColor = "red"
                $label_Computers1.Text = "Check logs."
            } #End if
            else{
                logMessage -Message "Checking if OU path exist..." -logLevel Info
                logMessage -Message "Supplied path exist." -logLevel Info

                $label_Computers1.ForeColor = "green"
                $label_Computers1.Text = "Ok"
            } #End else

        } #End if
        elseif ($ComboBox_Computers.SelectedIndex -eq 1) {
            #logMessage -Message "Checking if file path exist..." -logLevel Info
            logMessage -Message "Selecting computers from file currently is not supported." -logLevel Info
        } #End elseif
        else{
            logMessage -Message "Select from the dropdown menu one of the options." -logLevel Info
            $label_Computers1.ForeColor = "red"
            $label_Computers1.Text = "Select option"
        } #End else
        

    } #End button action
) #End button
$main_form.Controls.Add($Button_Computers)

$Button_Computers1 = New-Object System.Windows.Forms.Button
$Button_Computers1.Text = "Export as a .txt file"
$Button_Computers1.Location = New-Object System.Drawing.Point(570,190)
$Button_Computers1.Size = $buttonSize_1
$Button_Computers1.Add_Click(
    {
        
    } #End button action
) #End button
$main_form.Controls.Add($Button_Computers1)

<#
    Create a separator line
#>
$label_line_vertical_1 = New-Object System.Windows.Forms.Label
$label_line_vertical_1.Text = ""
$label_line_vertical_1.Width = 2
$label_line_vertical_1.Height = 410
$label_line_vertical_1.BorderStyle = "Fixed3D"
$label_line_vertical_1.Location = New-Object System.Drawing.Point(815,10)
$label_line_vertical_1.AutoSize = $false
$main_form.Controls.Add($label_line_vertical_1)

$label_line_horizontal_1 = New-Object System.Windows.Forms.Label
$label_line_horizontal_1.Text = ""
$label_line_horizontal_1.Width = 240
$label_line_horizontal_1.Height = 2
$label_line_horizontal_1.BorderStyle = "Fixed3D"
$label_line_horizontal_1.Location = New-Object System.Drawing.Point(830,75)
$label_line_horizontal_1.AutoSize = $false
$main_form.Controls.Add($label_line_horizontal_1)

$label_line_horizontal_2 = New-Object System.Windows.Forms.Label
$label_line_horizontal_2.Text = ""
$label_line_horizontal_2.Width = 240
$label_line_horizontal_2.Height = 2
$label_line_horizontal_2.BorderStyle = "Fixed3D"
$label_line_horizontal_2.Location = New-Object System.Drawing.Point(830,255)
$label_line_horizontal_2.AutoSize = $false
$main_form.Controls.Add($label_line_horizontal_2)


<#

        GUI part - Import and Export certificate

#>
$label_ImportExport = New-Object System.Windows.Forms.Label
$label_ImportExport.Text = "Import and Export certificate to the local computer"
$label_ImportExport.Location = New-Object System.Drawing.Point(860,10)
$label_ImportExport.AutoSize = $true
$main_form.Controls.Add($label_ImportExport)

$label_cert1_LocalPath = New-Object System.Windows.Forms.Label
$label_cert1_LocalPath.Text = "Local folder or file path"
$label_cert1_LocalPath.Location = New-Object System.Drawing.Point(820,30)
$label_cert1_LocalPath.AutoSize = $true 
$main_form.Controls.Add($label_cert1_LocalPath)

$label_cert1_export_key = New-Object System.Windows.Forms.Label
$label_cert1_export_key.Text = "Export Private key"
$label_cert1_export_key.Location = New-Object System.Drawing.Point(1090,30)
$label_cert1_export_key.AutoSize = $true
$main_form.Controls.Add($label_cert1_export_key)

$label_cert1_export_import = New-Object System.Windows.Forms.Label
$label_cert1_export_import.Text = "Don't press the buttons"
$label_cert1_export_import.ForeColor = "orange"
$label_cert1_export_import.Location = New-Object System.Drawing.Point(1060,50)
$label_cert1_export_import.AutoSize = $true
$main_form.Controls.Add($label_cert1_export_import)

$textBox_cert1_LocalPath = New-Object System.Windows.Forms.TextBox
$textBox_cert1_LocalPath.Location = New-Object System.Drawing.Point(940,30)
$textBox_cert1_LocalPath.Text = ""
$textBox_cert1_LocalPath.Width = 140
$textBox_cert1_LocalPath.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert1_LocalPath.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert1_LocalPath)

$comboBox_cert1_export_key = New-Object System.Windows.Forms.ComboBox
$comboBox_cert1_export_key.Width = 60
$comboBox_cert1_export_key.Items.Add("Yes")
$comboBox_cert1_export_key.Items.Add("No")
$comboBox_cert1_export_key.SelectedIndex = 1
$comboBox_cert1_export_key.DropDownStyle = 2
$comboBox_cert1_export_key.Location = New-Object System.Drawing.Point(1200,30)
$main_form.Controls.Add($comboBox_cert1_export_key)

$Button_cert1_export = New-Object System.Windows.Forms.Button
$Button_cert1_export.Text = "Export certificate"
$Button_cert1_export.Location = New-Object System.Drawing.Point(820,50)
$Button_cert1_export.Size = $buttonSize_1
$Button_cert1_export.Add_Click(
    {
        $label_cert1_export_import.Text = "Why did you pressed it?"
        logMessage -Message $label_cert1_export_import.Text -logLevel Info
    } #End button action
) #End button
$main_form.Controls.Add($Button_cert1_export)

$Button_cert1_import = New-Object System.Windows.Forms.Button
$Button_cert1_import.Text = "Import certificate"
$Button_cert1_import.Location = New-Object System.Drawing.Point(940,50)
$Button_cert1_import.Size = $buttonSize_1
$Button_cert1_import.Add_Click(
    {
        $label_cert1_export_import.Text = "Why did you pressed it?"
        logMessage -Message $label_cert1_export_import.Text -logLevel Info
        $summary_HelpForm.ShowDialog()
    } #End button action
) #End button
$main_form.Controls.Add($Button_cert1_import)


<#

        GUI part - Create self-signed encrypt/decrypt certificate

#>
$label_EncryptDecryptCertificate = New-Object System.Windows.Forms.Label
$label_EncryptDecryptCertificate.Text = "Create self-signed encrypt/decrypt certificate"
$label_EncryptDecryptCertificate.Location = New-Object System.Drawing.Point(860,80)
$label_EncryptDecryptCertificate.AutoSize = $true
$main_form.Controls.Add($label_EncryptDecryptCertificate)

$label_cert1_svcAccountName = New-Object System.Windows.Forms.Label
$label_cert1_svcAccountName.Text = "Enter service account"
$label_cert1_svcAccountName.Location = New-Object System.Drawing.Point(820,100)
$label_cert1_svcAccountName.AutoSize = $true
$main_form.Controls.Add($label_cert1_svcAccountName)

$label_cert1_months = New-Object System.Windows.Forms.Label
$label_cert1_months.Text = "Enter validity months"
$label_cert1_months.Location = New-Object System.Drawing.Point(820,120)
$label_cert1_months.AutoSize = $true 
$main_form.Controls.Add($label_cert1_months)

$label_cert1_create = New-Object System.Windows.Forms.Label
$label_cert1_create.Text = ""
$label_cert1_create.Location = New-Object System.Drawing.Point(940,140)
$label_cert1_create.AutoSize = $true
$main_form.Controls.Add($label_cert1_create)

$textBox_cert1_svcAccountName = New-Object System.Windows.Forms.TextBox
$textBox_cert1_svcAccountName.Location = New-Object System.Drawing.Point(940,100)
$textBox_cert1_svcAccountName.Text = ""
$textBox_cert1_svcAccountName.Width = 140
$textBox_cert1_svcAccountName.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert1_svcAccountName.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert1_svcAccountName)

$textBox_cert1_months = New-Object System.Windows.Forms.TextBox
$textBox_cert1_months.Location = New-Object System.Drawing.Point(940,120)
$textBox_cert1_months.Text = ""
$textBox_cert1_months.Width = 40
$textBox_cert1_months.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert1_months.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert1_months)

$Button_cert1_create = New-Object System.Windows.Forms.Button
$Button_cert1_create.Text = "Create certificate"
$Button_cert1_create.Location = New-Object System.Drawing.Point(820,140)
$Button_cert1_create.Size = $buttonSize_1
$Button_cert1_create.Add_Click(
    {
        $label_summary_HelpForm_1.Text = $label_cert1_svcAccountName.Text
        $label_summary_HelpForm_2.Text = $textBox_cert1_svcAccountName.Text
        $label_summary_HelpForm_3.Text = $label_cert1_months.Text
        $label_summary_HelpForm_4.Text = $textBox_cert1_months.Text

        logMessage -Message "Waiting user confirmation to continue." -logLevel Info
        $form_ExitResult = $summary_HelpForm.ShowDialog($main_form)
        if($form_ExitResult -eq [System.Windows.Forms.DialogResult]::OK){
            #Do nothing
            logMessage -Message "User confirmed to continue." -logLevel Info
            HelpFormNull
        } elseif($form_ExitResult -eq [System.Windows.Forms.DialogResult]::Cancel){
            logMessage -Message "User canceled the operation." -logLevel Info
            HelpFormNull
            return
        }

        logMessage -Message "Checking input values..." -logLevel Info
        if(($textBox_cert1_svcAccountName.Text.Length -ne 0) -and ($textBox_cert1_months.Text.Length -ne 0)){
            try {
                logMessage -Message "Starting the creation of the self-signed encrypt/decrypt certificate ..." -logLevel Info
                [Int]$temp = $textBox_cert1_months.Text
                CreateEncryptDecryptSelfSignedCertificate -svcAccountName $textBox_cert1_svcAccountName.Text -Months $textBox_cert1_months.Text
                $label_cert1_create.Text = "Complete."
                $label_cert1_create.ForeColor = "green"
                logMessage -Message $label_cert1_create.Text -logLevel Info

            } #End try
            catch [System.Management.Automation.ArgumentTransformationMetadataException]{
                $label_cert1_create.Text = "Months is not an int."
                $label_cert1_create.ForeColor = "red"
                logMessage -Message "Months is not an int." -logLevel Info
            } #End catch
            catch {
                $label_cert1_create.Text = "Check logs."
                $label_cert1_create.ForeColor = "red"

                $temp = $PSItem.Exception.Message
                logMessage -Message "$temp" -logLevel Error
                $temp = $PSItem.Exception.GetType().fullname
                logMessage -Message "Exception type is: $temp" -logLevel Info
                $temp = $PSItem.ScriptStackTrace
                logMessage -Message "Exception trace: $temp" -logLevel Info
            } #End catch
        } else{
            $label_cert1_create.Text = "No data"
            $label_cert1_create.ForeColor = "red"
            logMessage -Message $label_cert1_create.Text -logLevel Info
        } #End if
    } #End button action
) #End button
$main_form.Controls.Add($Button_cert1_create)


<#

        GUI part - Encrypt credentials

#>
$label_EncryptCredentials = New-Object System.Windows.Forms.Label
$label_EncryptCredentials.Text = "Encrypt credentials and save them to file"
$label_EncryptCredentials.Location = New-Object System.Drawing.Point(860,170)
$label_EncryptCredentials.AutoSize = $true
$main_form.Controls.Add($label_EncryptCredentials)

$label_EncryptCredentials_account = New-Object System.Windows.Forms.Label
$label_EncryptCredentials_account.Text = "Enter service account"
$label_EncryptCredentials_account.Location = New-Object System.Drawing.Point(820,190)
$label_EncryptCredentials_account.AutoSize = $true
$main_form.Controls.Add($label_EncryptCredentials_account)

$label_EncryptCredentials_SavePath = New-Object System.Windows.Forms.Label
$label_EncryptCredentials_SavePath.Text = "Save file location path"
$label_EncryptCredentials_SavePath.Location = New-Object System.Drawing.Point(820,210)
$label_EncryptCredentials_SavePath.AutoSize = $true
$main_form.Controls.Add($label_EncryptCredentials_SavePath)

$label_EncryptCredentials_1 = New-Object System.Windows.Forms.Label
$label_EncryptCredentials_1.Text = ""
$label_EncryptCredentials_1.Location = New-Object System.Drawing.Point(940,230)
$label_EncryptCredentials_1.AutoSize = $true
$main_form.Controls.Add($label_EncryptCredentials_1)

$textBox_EncryptCredentials_Account = New-Object System.Windows.Forms.TextBox
$textBox_EncryptCredentials_Account.Location = New-Object System.Drawing.Point(940,190)
$textBox_EncryptCredentials_Account.Text = ""
$textBox_EncryptCredentials_Account.Width = 140
$textBox_EncryptCredentials_Account.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_EncryptCredentials_Account.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_EncryptCredentials_Account)

$textBox_EncryptCredentials_SavePath = New-Object System.Windows.Forms.TextBox
$textBox_EncryptCredentials_SavePath.Location = New-Object System.Drawing.Point(940,210)
$textBox_EncryptCredentials_SavePath.Text = ""
$textBox_EncryptCredentials_SavePath.Width = 140
$textBox_EncryptCredentials_SavePath.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_EncryptCredentials_SavePath.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_EncryptCredentials_SavePath)

$Button_EncryptCredentials = New-Object System.Windows.Forms.Button
$Button_EncryptCredentials.Text = "Encrypt credentials"
$Button_EncryptCredentials.Location = New-Object System.Drawing.Point(820,230)
$Button_EncryptCredentials.Size = $buttonSize_1
$Button_EncryptCredentials.Add_Click(
    {
        $label_summary_HelpForm_1.Text = $label_EncryptCredentials_account.Text
        $label_summary_HelpForm_2.Text = $textBox_EncryptCredentials_Account.Text
        $label_summary_HelpForm_3.Text = $label_EncryptCredentials_SavePath.Text
        $label_summary_HelpForm_4.Text = $textBox_EncryptCredentials_SavePath.Text

        logMessage -Message "Waiting user confirmation to continue." -logLevel Info
        $form_ExitResult = $summary_HelpForm.ShowDialog($main_form)
        if($form_ExitResult -eq [System.Windows.Forms.DialogResult]::OK){
            #Do nothing
            logMessage -Message "User confirmed to continue." -logLevel Info
            HelpFormNull
        } elseif($form_ExitResult -eq [System.Windows.Forms.DialogResult]::Cancel){
            logMessage -Message "User canceled the operation." -logLevel Info
            HelpFormNull
            return
        }

        $temp = $true
        logMessage -Message "Checking folder path existance ..." -logLevel Info
        if( -not ([string]::IsNullOrEmpty($textBox_EncryptCredentials_SavePath.Text)) -and (Test-Path -Path $textBox_EncryptCredentials_SavePath.Text -ErrorAction SilentlyContinue)){
            $label_EncryptCredentials_1.ForeColor = "green"
            $label_EncryptCredentials_1.Text = "Path exists."
            logMessage -Message $label_EncryptCredentials_1.Text -logLevel Info
        } elseif([string]::IsNullOrEmpty($textBox_EncryptCredentials_SavePath.Text)){
            $label_EncryptCredentials_1.ForeColor = "red"
            $label_EncryptCredentials_1.Text = "No data"
            logMessage -Message $label_EncryptCredentials_1.Text -logLevel Info
            $temp = $false
        } else {
            $label_EncryptCredentials_1.ForeColor = "red"
            $label_EncryptCredentials_1.Text = "Path does not exist."
            logMessage -Message $label_EncryptCredentials_1.Text -logLevel Info
            $temp = $false
        } #End if

        try {
            if( -not ([string]::IsNullOrEmpty($textBox_EncryptCredentials_account.Text)) -and $temp){
                $return_boolean = EncryptAccountCredentials -svcAccountName $textBox_EncryptCredentials_account.Text -SaveFilePath $textBox_EncryptCredentials_SavePath.Text
                if ($return_boolean) {
                    $label_EncryptCredentials_1.ForeColor = "green"
                    $label_EncryptCredentials_1.Text = "Complete"
                    logMessage -Message "Task has finished successfully." -logLevel Info
                } else{
                    $label_EncryptCredentials_1.ForeColor = "red"
                    $label_EncryptCredentials_1.Text = "Check logs"
                } #End if
            } elseif (([string]::IsNullOrEmpty($textBox_EncryptCredentials_account.Text))) {
                $label_EncryptCredentials_1.ForeColor = "red"
                $label_EncryptCredentials_1.Text = "No data"
                logMessage -Message $label_EncryptCredentials_1.Text -logLevel Info
            } #End if
        } #End try
        catch {
            $label_EncryptCredentials_1.ForeColor = "red"
            $label_EncryptCredentials_1.Text = "Check logs"

            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        } #End catch
    } #End button action
) #End button
$main_form.Controls.Add($Button_EncryptCredentials)


<#

        GUI part - Create self-signed code signing certificate

#>
$label_CodeSigningCertificate = New-Object System.Windows.Forms.Label
$label_CodeSigningCertificate.Text = "Create self-signed code signing certificate"
$label_CodeSigningCertificate.Location = New-Object System.Drawing.Point(860,260)
$label_CodeSigningCertificate.AutoSize = $true
$main_form.Controls.Add($label_CodeSigningCertificate)

$label_cert2_svcAccountName = New-Object System.Windows.Forms.Label
$label_cert2_svcAccountName.Text = "Certificate name"
$label_cert2_svcAccountName.Location = New-Object System.Drawing.Point(820,280)
$label_cert2_svcAccountName.AutoSize = $true
$main_form.Controls.Add($label_cert2_svcAccountName)

$label_cert2_svcAccountName_1 = New-Object System.Windows.Forms.Label
$label_cert2_svcAccountName_1.Text = ""
$label_cert2_svcAccountName_1.Location = New-Object System.Drawing.Point(1050,280)
$label_cert2_svcAccountName_1.AutoSize = $true
$main_form.Controls.Add($label_cert2_svcAccountName_1)

$label_cert2_months = New-Object System.Windows.Forms.Label
$label_cert2_months.Text = "Months of validity"
$label_cert2_months.Location = New-Object System.Drawing.Point(820,300)
$label_cert2_months.AutoSize = $true 
$main_form.Controls.Add($label_cert2_months)

$label_cert2_create = New-Object System.Windows.Forms.Label
$label_cert2_create.Text = ""
$label_cert2_create.Location = New-Object System.Drawing.Point(940,320)
$label_cert2_create.AutoSize = $true
$main_form.Controls.Add($label_cert2_create)

$textBox_cert2_svcAccountName = New-Object System.Windows.Forms.TextBox
$textBox_cert2_svcAccountName.Location = New-Object System.Drawing.Point(940,280)
$textBox_cert2_svcAccountName.Text = ""
$textBox_cert2_svcAccountName.Width = 100
$textBox_cert2_svcAccountName.Add_Click( { $this.SelectAll(); $this.Focus() ; $label_cert2_svcAccountName_1.Text = "-SelfSignedCodeSigningCert"})
$textBox_cert2_svcAccountName.Add_Gotfocus( { $this.SelectAll(); $this.Focus() ; $label_cert2_svcAccountName_1.Text = "-SelfSignedCodeSigningCert"})
$main_form.Controls.Add($textBox_cert2_svcAccountName)

$textBox_cert2_months = New-Object System.Windows.Forms.TextBox
$textBox_cert2_months.Location = New-Object System.Drawing.Point(940,300)
$textBox_cert2_months.Text = ""
$textBox_cert2_months.Width = 40
$textBox_cert2_months.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert2_months.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert2_months)

$Button_cert2_create = New-Object System.Windows.Forms.Button
$Button_cert2_create.Text = "Create certificate"
$Button_cert2_create.Location = New-Object System.Drawing.Point(820,320)
$Button_cert2_create.Size = $buttonSize_1
$Button_cert2_create.Add_Click(
    {
        $label_summary_HelpForm_1.Text = $label_cert2_svcAccountName.Text
        $label_summary_HelpForm_2.Text = $textBox_cert2_svcAccountName.Text+"-SelfSignedCodeSigningCert"
        $label_summary_HelpForm_3.Text = $label_cert2_months.Text
        $label_summary_HelpForm_4.Text = $textBox_cert2_months.Text

        logMessage -Message "Waiting user confirmation to continue." -logLevel Info
        $form_ExitResult = $summary_HelpForm.ShowDialog($main_form)
        if($form_ExitResult -eq [System.Windows.Forms.DialogResult]::OK){
            #Do nothing
            logMessage -Message "User confirmed to continue." -logLevel Info
            HelpFormNull
        } elseif($form_ExitResult -eq [System.Windows.Forms.DialogResult]::Cancel){
            logMessage -Message "User canceled the operation." -logLevel Info
            HelpFormNull
            return
        }

        if(($textBox_cert2_svcAccountName.Text.Length -ne 0) -and ($textBox_cert2_months.Text.Length -ne 0)){
            try {
                logMessage -Message "Starting creation of the certificate..." -logLevel Info
                [Int]$temp = $textBox_cert2_months.Text
                CreateCodeSigningSelfSignedCertificate -svcAccountName $textBox_cert2_svcAccountName.Text -Months $textBox_cert2_months.Text
                $label_cert2_create.Text = "Complete."
                $label_cert2_create.ForeColor = "green"
                logMessage -Message $label_cert2_create.Text -logLevel Info
            } catch [System.Management.Automation.ArgumentTransformationMetadataException]{
                $label_cert2_create.Text = "Months is not an int."
                $label_cert2_create.ForeColor = "red"
                logMessage -Message "Months is not an int." -logLevel Info
            } catch {
                $label_cert2_create.Text = "Check logs"
                $label_cert2_create.ForeColor = "red"

                $temp = $PSItem.Exception.Message
                logMessage -Message "$temp" -logLevel Error
                $temp = $PSItem.Exception.GetType().fullname
                logMessage -Message "Exception type is: $temp" -logLevel Info
                $temp = $PSItem.ScriptStackTrace
                logMessage -Message "Exception trace: $temp" -logLevel Info
            } #End catch
        } else{
            logMessage -Message "Starting creation of the certificate..." -logLevel Info
            $label_cert2_create.Text = "No data"
            $label_cert2_create.ForeColor = "red"
            logMessage -Message $label_cert2_create.Text -logLevel Info
        } #End if
    } #End button action
) #End button
$main_form.Controls.Add($Button_cert2_create)


<#

        GUI part - Sign PowerShell scripts

#>
$label_cert2_CodeSignScript = New-Object System.Windows.Forms.Label
$label_cert2_CodeSignScript.Text = "Sign PowerShell script or folder with scripts"
$label_cert2_CodeSignScript.Location = New-Object System.Drawing.Point(860,350)
$label_cert2_CodeSignScript.AutoSize = $true 
$main_form.Controls.Add($label_cert2_CodeSignScript)

$label_cert2_CodeSignScript_certName = New-Object System.Windows.Forms.Label
$label_cert2_CodeSignScript_certName.Text = "Certificate name"
$label_cert2_CodeSignScript_certName.Location = New-Object System.Drawing.Point(820,370)
$label_cert2_CodeSignScript_certName.AutoSize = $true
$main_form.Controls.Add($label_cert2_CodeSignScript_certName)

$label_cert2_CodeSignScript_Path = New-Object System.Windows.Forms.Label
$label_cert2_CodeSignScript_Path.Text = "File or Folder path"
$label_cert2_CodeSignScript_Path.Location = New-Object System.Drawing.Point(820,390)
$label_cert2_CodeSignScript_Path.AutoSize = $true
$main_form.Controls.Add($label_cert2_CodeSignScript_Path)

$label_cert2_CodeSignScript_1 = New-Object System.Windows.Forms.Label
$label_cert2_CodeSignScript_1.Text = ""
$label_cert2_CodeSignScript_1.Location = New-Object System.Drawing.Point(940,410)
$label_cert2_CodeSignScript_1.AutoSize = $true
$main_form.Controls.Add($label_cert2_CodeSignScript_1)

$textBox_cert2_CodeSignScript_certName = New-Object System.Windows.Forms.TextBox
$textBox_cert2_CodeSignScript_certName.Location = New-Object System.Drawing.Point(940,370)
$textBox_cert2_CodeSignScript_certName.Text = ""
$textBox_cert2_CodeSignScript_certName.Width = 140
$textBox_cert2_CodeSignScript_certName.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert2_CodeSignScript_certName.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert2_CodeSignScript_certName)

$textBox_cert2_CodeSignScript_Path = New-Object System.Windows.Forms.TextBox
$textBox_cert2_CodeSignScript_Path.Location = New-Object System.Drawing.Point(940,390)
$textBox_cert2_CodeSignScript_Path.Text = ""
$textBox_cert2_CodeSignScript_Path.Width = 140
$textBox_cert2_CodeSignScript_Path.Add_Click( { $this.SelectAll(); $this.Focus() })
$textBox_cert2_CodeSignScript_Path.Add_Gotfocus( { $this.SelectAll(); $this.Focus() })
$main_form.Controls.Add($textBox_cert2_CodeSignScript_Path)

$Button_cert2_sign = New-Object System.Windows.Forms.Button
$Button_cert2_sign.Text = "Sign PS files"
$Button_cert2_sign.Location = New-Object System.Drawing.Point(820,410)
$Button_cert2_sign.Size = $buttonSize_1
$Button_cert2_sign.Add_Click(
    {
        $label_summary_HelpForm_1.Text = $label_cert2_CodeSignScript_certName.Text
        $label_summary_HelpForm_2.Text = $textBox_cert2_CodeSignScript_certName.Text
        $label_summary_HelpForm_3.Text = $label_cert2_CodeSignScript_Path.Text
        $label_summary_HelpForm_4.Text = $textBox_cert2_CodeSignScript_Path.Text

        logMessage -Message "Waiting user confirmation to continue." -logLevel Info
        $form_ExitResult = $summary_HelpForm.ShowDialog($main_form)
        if($form_ExitResult -eq [System.Windows.Forms.DialogResult]::OK){
            #Do nothing
            logMessage -Message "User confirmed to continue." -logLevel Info
            HelpFormNull
        } elseif($form_ExitResult -eq [System.Windows.Forms.DialogResult]::Cancel){
            logMessage -Message "User canceled the operation." -logLevel Info
            HelpFormNull
            return
        }

        $temp = $true
        logMessage -Message "Checking folder path existance ..." -logLevel Info
        if( -not ([string]::IsNullOrEmpty($textBox_cert2_CodeSignScript_Path.Text)) -and (Test-Path -Path $textBox_cert2_CodeSignScript_Path.Text -ErrorAction SilentlyContinue)){
            $label_cert2_CodeSignScript_1.ForeColor = "green"
            $label_cert2_CodeSignScript_1.Text = "Path exists."
            logMessage -Message $label_cert2_CodeSignScript_1.Text -logLevel Info
        } elseif([string]::IsNullOrEmpty($textBox_cert2_CodeSignScript_Path.Text)){
            $label_cert2_CodeSignScript_1.ForeColor = "red"
            $label_cert2_CodeSignScript_1.Text = "No data"
            logMessage -Message $label_cert2_CodeSignScript_1.Text -logLevel Info
            $temp = $false
        } else {
            $label_cert2_CodeSignScript_1.ForeColor = "red"
            $label_cert2_CodeSignScript_1.Text = "Path does not exist."
            logMessage -Message $label_cert2_CodeSignScript_1.Text -logLevel Info
            $temp = $false
        } #End if
        
        

        try {
            if( -not ([string]::IsNullOrEmpty($textBox_cert2_CodeSignScript_certName.Text)) -and $temp){
                $return_boolean = SignPSScripts -svcAccountName $textBox_cert2_CodeSignScript_certName.Text -filesPath $textBox_cert2_CodeSignScript_Path.Text
                if ($return_boolean) {
                    $label_cert2_CodeSignScript_1.ForeColor = "green"
                    $label_cert2_CodeSignScript_1.Text = "Complete"
                    logMessage -Message "Task has finished successfully." -logLevel Info
                } else {
                    $label_cert2_CodeSignScript_1.ForeColor = "red"
                    $label_cert2_CodeSignScript_1.Text = "Check logs"
                } #End if   
            } elseif (([string]::IsNullOrEmpty($textBox_cert2_CodeSignScript_certName.Text)) -and $temp){
                $label_cert2_CodeSignScript_1.ForeColor = "red"
                $label_cert2_CodeSignScript_1.Text = "Enter script name"
                logMessage -Message $label_cert2_CodeSignScript_1.Text -logLevel Info
            } #End if
        } #End try
        catch {
            $label_cert2_CodeSignScript_1.ForeColor = "red"
            $label_cert2_CodeSignScript_1.Text = "Check logs"

            $temp = $PSItem.Exception.Message
            logMessage -Message "$temp" -logLevel Error
            $temp = $PSItem.Exception.GetType().fullname
            logMessage -Message "Exception type is: $temp" -logLevel Info
            $temp = $PSItem.ScriptStackTrace
            logMessage -Message "Exception trace: $temp" -logLevel Info
        } #End catch
    } #End button action
) #End Button
$main_form.Controls.Add($Button_cert2_sign)


<#
        Display logs in GUI
#>
$label_outbox = New-Object System.Windows.Forms.Label
$label_outbox.Text = "Logs display level"
$label_outbox.Location = New-Object System.Drawing.Size(700,385)
$label_outbox.AutoSize = $true
$main_form.Controls.Add($label_outbox)

$textBox_outbox = New-Object System.Windows.Forms.TextBox
$textBox_outbox.Text = Get-Content $logPath -raw
$textBox_outbox.Location = New-Object System.Drawing.Size(700,430)
$textBox_outbox.Size = New-Object System.Drawing.Size(565,270)
$textBox_outbox.MultiLine = $True
$textBox_outbox.ScrollBars = "Vertical"
$main_form.Controls.Add($textBox_outbox)

$comboBox_logs = New-Object System.Windows.Forms.ComboBox
$comboBox_logs.Width = 70
$comboBox_logs.Items.Add("INFO")
$comboBox_logs.Items.Add("WARN")
$comboBox_logs.Items.Add("ERROR")
$comboBox_logs_SelectedIndexChanged = {
    if ($comboBox_logs.text -eq "ERROR") {
        $logs_search = @("ERROR")
        $fileContents = Get-Content $logPath | Select-String -Pattern $logs_search -SimpleMatch
        $textBox_outbox.Text = ""
        foreach($item in $fileContents){
            $textBox_outbox.AppendText("$item `r`n")
        } #End foreach
        
    } elseif ($comboBox_logs.text -eq "WARN") {
        $logs_search = @("ERROR","WARN")
        $fileContents = Get-Content $logPath | Select-String -Pattern $logs_search -SimpleMatch
        $textBox_outbox.Text = ""
        foreach($item in $fileContents){
            $textBox_outbox.AppendText("$item `r`n")
        } #End foreach
    } elseif ($comboBox_logs.text -eq "INFO") {
        $logs_search = @("ERROR","WARN","INFO")
        $fileContents = Get-Content $logPath | Select-String -Pattern $logs_search -SimpleMatch
        $textBox_outbox.Text = ""
        foreach($item in $fileContents){
            $textBox_outbox.AppendText("$item `r`n")
        } #End foreach
    } #End if
} #End comboBox
$comboBox_logs.add_SelectedIndexChanged($comboBox_logs_SelectedIndexChanged)
$comboBox_logs.SelectedIndex = 0
$comboBox_logs.DropDownStyle = 2
$comboBox_logs.Location = New-Object System.Drawing.Size(700,405)
$main_form.Controls.Add($comboBox_logs)


<#

    Create second GUI form used to display summary and ask for confirmation

#>
#Begin $summary_HelpForm
$summary_HelpForm = New-Object System.Windows.Forms.Form
$summary_HelpForm.Text ='Install Apllication GUI'
$summary_HelpForm.Width = 360
$summary_HelpForm.Height = 180
$summary_HelpForm.AutoSize = $true
$summary_HelpForm.StartPosition = "CenterScreen"

#$Summary_HelpForm labels
$label_summary_HelpForm = New-Object System.Windows.Forms.Label
$label_summary_HelpForm.Text = "Summary"
$label_summary_HelpForm.Location = New-Object System.Drawing.Size(150,10)
$label_summary_HelpForm.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm)

$label_summary_HelpForm_1 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_1.Text = ""
$label_summary_HelpForm_1.Location = New-Object System.Drawing.Size(20,50)
$label_summary_HelpForm_1.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_1)

$label_summary_HelpForm_2 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_2.Text = ""
$label_summary_HelpForm_2.Location = New-Object System.Drawing.Size(140,50)
$label_summary_HelpForm_2.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_2)

$label_summary_HelpForm_3 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_3.Text = ""
$label_summary_HelpForm_3.Location = New-Object System.Drawing.Size(20,80)
$label_summary_HelpForm_3.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_3)

$label_summary_HelpForm_4 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_4.Text = ""
$label_summary_HelpForm_4.Location = New-Object System.Drawing.Size(140,80)
$label_summary_HelpForm_4.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_4)

$label_summary_HelpForm_5 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_5.Text = ""
$label_summary_HelpForm_5.Location = New-Object System.Drawing.Size(20,110)
$label_summary_HelpForm_5.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_5)

$label_summary_HelpForm_6 = New-Object System.Windows.Forms.Label
$label_summary_HelpForm_6.Text = ""
$label_summary_HelpForm_6.Location = New-Object System.Drawing.Size(140,110)
$label_summary_HelpForm_6.AutoSize = $true
$summary_HelpForm.Controls.Add($label_summary_HelpForm_6)

$button_Summary_HelpForm_cancel = New-Object System.Windows.Forms.Button
$button_Summary_HelpForm_cancel.Text = "Cancel"
$button_Summary_HelpForm_cancel.Location = New-Object System.Drawing.Point(20,150)
$button_Summary_HelpForm_cancel.Size = $buttonSize_3
$button_Summary_HelpForm_cancel.Add_Click(
    {
        $summary_HelpForm.Close()
    }
)
$button_Summary_HelpForm_cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel
$summary_HelpForm.CancelButton = $button_Summary_HelpForm_cancel
$summary_HelpForm.Controls.Add($button_Summary_HelpForm_cancel)

$button_Summary_HelpForm_continue = New-Object System.Windows.Forms.Button
$button_Summary_HelpForm_continue.Text = "Continue"
$button_Summary_HelpForm_continue.Location = New-Object System.Drawing.Point(240,150)
$button_Summary_HelpForm_continue.Size = $buttonSize_3
$button_Summary_HelpForm_continue.Add_Click(
    {
        $summary_HelpForm.Close()
    }
)
$button_Summary_HelpForm_continue.DialogResult = [System.Windows.Forms.DialogResult]::OK
$summary_HelpForm.AcceptButton = $button_Summary_HelpForm_continue
$summary_HelpForm.Controls.Add($button_Summary_HelpForm_continue)
#End of $summary_HelpForm


<#
    Display the main GUI Form
#>
$main_form.ShowDialog()

