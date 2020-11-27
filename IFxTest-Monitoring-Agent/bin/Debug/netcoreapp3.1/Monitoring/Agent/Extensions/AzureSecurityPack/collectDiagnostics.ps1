<#----------------------------------------------------------------------------------------------------------------------------------- 
:: <copyright file="collectDiagnostics.ps1" company="Microsoft">
::     Copyright (c) Microsoft Corporation.  All rights reserved. 
:: </copyright> 
:: 
:: <summary> 
:: Tool to collect Diagonostic Data specific to AzSecPack.
:: </summary>
:: ----------------------------------------------------------------------------------------------------------------------------------

::------------------------------------------------------------------------------------------------------------------------------------
::	 												collectDiagnostics.ps1
::------------------------------------------------------------------------------------------------------------------------------------
::-- Tool to collect Diagonostic Data specific to ASM.
::-- This tool can be either run via command line manually
::-- or using some other process to launch it, it gets 
::-- all the logs/relevant information needed to determine
::-- what might be wrong on a particular node.
::-- Usage : 
::--	(i).\collectDiagnostics.ps1 <path to Monitoring Data Directory> 
::--    (ii).\collectDiagnostics.ps1 -monitoringPath <path to Monitoring Data Directory> -readLogPath <path to log file Directory> 
::--                                 -outputLogPath <path to output Directory>
::--        readLogPath and outputLogPath are not mandatory
::-- 1. Cleans up the diagnosticsData directory if exists else creates one
::-- 2. Collects all the logs and copies them to the diagnosticsData dir:
::--	a. List of all processes running on the system in : tasklist.txt
::--	b. Gets the list of all publishers on the machine in : AllPublishers.txt
::--	c. Executes command "wevtutil gp Microsoft-Azure-Security-Scanner" 
::--		and the output is copied to : ASMPublisher.txt
::--	d. Checks whether the Antimalware engine is running; executes command
::--		"sc query msmpsvc" and copies output to msmpsvc.txt 
::--	e. Executes command "wevtutil gp Microsoft-Windows-AppLocker" 
::--		and the output is copied to : AppLockerPublisher.txt
::--    f. Copies local AppLocker events from all four Applocker channels into diagnostics data directory 
::--    g. Gets local and effective AppLocker policy in xml format and copies policy to AppLockerLocalPolicy.xml and AppLockerEffectivePolicy.xml
::-- 	h. Copies the contents of <MonitoringDataDirectory>/Packages,Configurations,Packets to diagnosticsData dir
::--	i. Converts Scanner specific MA tables AsmScannerData/AsmScannerDefaultEvents/AsmScannerStatusEvents/TraceEvents from tsf to CSV
::-- 		and copies the corresponding CSV files as is to the dataDiagnostics dir.
::--	j. Converts AppLocker specific MA tables AppLockerEXEDLL/AppLockerMSISCRIPT/AppLockerPKGAPPDEPLOY/AppLockerPKGAPPEXEC from tsf to CSV
::-- 		and copies the corresponding CSV files as is to the dataDiagnostics dir.
::--    k. Copy all the *.log, *xml, *.json, *er files from current dir, readLogPath, $env:APPDATA\AzureSecurityPack, $env:TEMP\AzureSecurityPack 
::--        to $outputLogPath\currentDir, $outputLogPath\specifiedDirLog, $outputLogPath\appdataLog, $outputLogPath\tempLog.
::--    l. Get SecurityScanMgr and MonAgentHost process details and log to SecurityScanMgrProcessInfo.log and MonAgentHostProcessInfo.log;
::--    m. Status of copying table and logs are in copyTableStatus.log, copyLogStatus.log and collectDiagnosticsStatusLog.log
::-- ******************************************************************************************************************************************
::-- 3.	Once all the relevant information is copied over to the dataDiagnostics dir,  
::--	we zip it : %computername%_diagnosticsData_%currentDate%_%currentTime%.zip
::-- 4. This zip file can be pulled to get all the relevant diagnostic data from a particular node.#>

Param([Parameter(Mandatory=$true)]
      [string] $monitoringPath = "", 
      [string] $readLogPath = "",
      [string] $outputLogPath = "")

$logFile = "collectDiagnosticsStatusLog.log"
# Set up output path
if ($outputLogPath = "") { 
    $outputLogPath = $env:SystemDrive;   
}

$outputPath = "$outputLogPath\diagnosticsData";
$zipDir = "$outputLogPath\DiagnosticsZipDir";

$currentDate = (Get-Date).ToString("MMddyyyy");
$currentTime = (Get-Date).ToString("HHmm");
$computerName = $env:COMPUTERNAME;
$zipPath = $zipDir + "\" + $computerName + "_diagnosticsData_" + $currentDate + "_" + $currentTime + ".zip";

# Helper function
# Set file/dir inheritance to false and remove user access
Function SetFilePermission (
		[parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$path
	)
{
    icacls $path /inheritance:d /T;
	icacls $path /remove:g Users /T;
}

# Helper function
# Get Process id, image path, args and EnvironmentVariables for a process
Function GetProcessDetail(
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$processName
    ){

    $processActive = Get-Process -Name $processName -ErrorAction SilentlyContinue
    if($processActive -eq $null) {
        Write-Output "Process $processName not Found"
    }else { 
        Write-Output "Get infomation for process $processName :"
        $processDetails = Get-Process -Name $processName;
        foreach ($processDetail in $processDetails) { 
            Write-Output "PID = " $processDetail.Id;
            Write-Output "ImagePath = " $processDetail.Path;
            $startInfo = $processDetail.StartInfo;
            Write-Output "Args = "
            foreach($arg in $startInfo.Arguments) {
                Write-Output $arg;
            }
            Write-Output "EnvironmentVariables ="
            foreach ($envVaribable in $startInfo.EnvironmentVariables.Keys) {
                $value = $startInfo.EnvironmentVariables[$envVaribable];
                Write-Output "$envVaribable : $value";
            }            
        }
    }
}

# Helper function
# Convert tsf to csv and copy it to output path
Function ConvertAndCopyTablesAzSecPack (
		[parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$tablePath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$table2CSVPath,
        [parameter(Mandatory=$true)]
        [ValidateNotNullOrEmpty()]$tsfFileList
	){

    Tee-Object $outputPath\$logFile -Append -InputObject "ConvertAndCopyTablesAzSecPack function called the table path passed as an argument is $tablePath and table2csv path is $table2CSVPath" | Write-Host
	Tee-Object $outputPath\$logFile -Append -InputObject "The outputpath is $outputPath" | Write-Host
	Tee-Object $outputPath\$logFile -Append -InputObject "The table2csvpath is $table2CSVPath" | Write-Host
    
    foreach ($tsfFile in $tsfFileList) {
        if (Test-Path "$tablePath\$tsfFile.tsf") {
            Tee-Object $outputPath\$logFile -Append -InputObject "Found $tablePath\$tsfFile.tsf trying to convert it to CSV and copying to diagnosticData directory." | Write-Host
            Tee-Object $outputPath\$logFile -Append -InputObject "The command is $table2CSVPath\table2csv.exe $tablePath\$tsfFile.tsf" | Write-Host		    
		    & $table2CSVPath\table2csv.exe $tablePath\$tsfFile.tsf
		    robocopy $tablePath $outputPath "$tsfFile.csv" /log+:$outputPath\copyTableStatus.log /tee
	    }else{
            Tee-Object $outputPath\$logFile -Append -InputObject "$tablePath\$tsfFile.tsf not found." | Write-Host
        }
    }    
}

if (Test-Path $outputPath) {
   Remove-Item -r $outputPath;        
}

New-Item $outputPath -type directory;
SetFilePermission -path $outputPath;      

if (Test-Path $zipPath) {
    Remove-Item -r $zipPath;
}

if ((Test-Path $zipDir) -eq $false) {
    New-Item $zipDir -type directory;  
    SetFilePermission -path $zipDir;
}

Tee-Object $outputPath\$logFile -Append -InputObject "Collect the list of processes running on the system right now at : $outputPath\tasklist.txt." | Write-Host
tasklist > $outputPath\tasklist.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Collect the list of all the Publishers on this node at : $outputPath\AllPublishers.txt." | Write-Host
wevtutil ep > $outputPath\AllPublishers.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the Security-Scanner Publisher exists; results at : $outputPath\ASMPublisher.txt." | Write-Host
wevtutil gp Microsoft-Azure-Security-Scanner > $outputPath\ASMPublisher.txt 2>&1

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the Microsoft AntiMalware engine is running on the system; result at : $outputPath\msmpsvc.txt." | Write-Host
sc query msmpsvc > $outputPath\msmpsvc.txt 2>&1

Tee-Object $outputPath\$logFile -Append -InputObject "Verify whether the AppLocker Publisher exists; results at : $outputPath\AppLockerPublisher.txt." | Write-Host
wevtutil gp Microsoft-Windows-AppLocker > $outputPath\AppLockerPublisher.txt

Tee-Object $outputPath\$logFile -Append -InputObject "Copy AppLocker event files to $outputPath" | Write-Host
wevtutil epl "Microsoft-windows-AppLocker/EXE and DLL" $outputPath\AppLockerEXEDLL.evtx
wevtutil epl "Microsoft-Windows-AppLocker/MSI and Script" $outputPath\AppLockerMSISCRIPT.evtx
wevtutil epl "Microsoft-Windows-AppLocker/Packaged app-Deployment" $outputPath\AppLockerPKGAPPDEPLOY.evtx
wevtutil epl "Microsoft-Windows-AppLocker/Packaged app-Execution" $outputPath\AppLockerPKGAPPEXEC.evtx

Tee-Object $outputPath\$logFile -Append -InputObject "Get local AppLocker policy; results at : $outputPath\AppLockerLocalPolicy.xml." | Write-Host
Get-AppLockerPolicy -Local -Xml > $outputPath\AppLockerLocalPolicy.xml

Tee-Object $outputPath\$logFile -Append -InputObject "Get effective AppLocker policy; results at : $outputPath\AppLockerEffectivePolicy.xml." | Write-Host
Get-AppLockerPolicy -Effective -Xml > $outputPath\AppLockerEffectivePolicy.xml

# Copy Configuration, Package and Packets dir under monitoringPath to outputPath
if (($monitoringPath -eq "") -or ((Test-Path $monitoringPath) -eq $false)) {
    Tee-Object $outputPath\$logFile -Append -InputObject "The monitoring data directoiry is not specified or doesn't exist." | Write-Host
}else {
    if (Test-Path $monitoringPath\Configuration) {
        robocopy $monitoringPath\Configuration $outputPath\Configuration /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Configuration directory under monitoring data directory not found." | Write-Host
    }

    if (Test-Path $monitoringPath\Package) {
        robocopy $monitoringPath\Package $outputPath\Package /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Package directory under monitoring data directory not found." | Write-Host
    }

    if (Test-Path $monitoringPath\Packets) {
        robocopy $monitoringPath\Packets $outputPath\Packets /E /log+:$outputPath\copyLogStatus.log /tee
    }else {
        Tee-Object $outputPath\$logFile -Append -InputObject "The Packets directory under monitoring data directory not found." | Write-Host
    }
}
    
# Convert and copy tables under monitoringPath to output path
$tablePath = "$monitoringPath\Tables";
$currentPath = split-path -parent $MyInvocation.MyCommand.Definition;
$table2CSVPath = (get-item $currentPath).parent.parent.FullName;
$tsfFileList = "AsmScannerData", "AsmScannerDefaultEvents", "AsmScannerStatusEvents", "TraceEvents", "MAEventTable", "AppLockerEXEDLL", "AppLockerMSISCRIPT", "AppLockerPKGAPPDEPLOY", "AppLockerPKGAPPEXEC";

ConvertAndCopyTablesAzSecPack -tablePath $tablePath -table2CSVPath $table2CSVPath -tsfFileList $tsfFileList

# Copy all log, er, json and xml files from current dir, specified dir, $env:APPDATA\AzureSecurityPack and $env:TEMP\AzureSecurityPack to output path
Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in current directory to $outputPath\currentDirLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $currentPath $outputPath\currentDirLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee

if ($readLogPath -eq "" -or (Test-Path $readLogPath) -eq $false) {
    Tee-Object $outputPath\$logFile -Append -InputObject "readLogPath not specified or not found" | Write-Host
}else {
    Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in specified directory $readLogPath to $outputPath\specifiedDirLog, and status to $outputPath\copyLogStatus.log" | Write-Host
    robocopy $readLogPath $outputPath\specifiedDirLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee
}

Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in $env:APPDATA\AzureSecurityPack to $outputPath\appdataLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $env:APPDATA\AzureSecurityPack $outputPath\appdataLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee

Tee-Object $outputPath\$logFile -Append -InputObject "Copying all logs in $env:TEMP\AzureSecurityPack to $outputPath\tempLog, and status to $outputPath\copyLogStatus.log" | Write-Host
robocopy $env:TEMP\AzureSecurityPack $outputPath\tempLog *.log *.er *.json *.xml /E /log+:$outputPath\copyLogStatus.log /tee


# Get SecurityScanMgr and MonAgentHost process details and log to $outputPath
GetProcessDetail -processName SecurityScanMgr >> $outputPath\SecurityScanMgrProcessInfo.log;
GetProcessDetail -processName MonAgentHost >> $outputPath\MonAgentHostProcessInfo.log;

# Zip all files
Set-Content -path $zipPath -value ("PK" + [char]5 + [char]6 + ("$([char]0)" * 18)) -ErrorAction Stop
$zipfile = $zipPath | Get-Item -ErrorAction Stop
$zipfile.IsReadOnly = $false  
#Creating Shell.Application
$shellApp = New-Object -com shell.application
$zipPackage = $shellApp.NameSpace($zipfile.fullname)
$target = Get-Item -Path $outputPath
$zipPackage.CopyHere($target.FullName)
# SIG # Begin signature block
# MIIjewYJKoZIhvcNAQcCoIIjbDCCI2gCAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCAi9w2dFgg6nz2b
# 7vV6PE1sOz4QfSrG5RJw8BY8UcHWsaCCDXYwggX0MIID3KADAgECAhMzAAABUMiP
# lnfeTPFHAAAAAAFQMA0GCSqGSIb3DQEBCwUAMH4xCzAJBgNVBAYTAlVTMRMwEQYD
# VQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNpZ25p
# bmcgUENBIDIwMTEwHhcNMTkwNTAyMjEzNzQ1WhcNMjAwNTAyMjEzNzQ1WjB0MQsw
# CQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9u
# ZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMR4wHAYDVQQDExVNaWNy
# b3NvZnQgQ29ycG9yYXRpb24wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCh2V193EGtu49awDgcJ1E8WB5mAim/gAFVpWUVOlk/haZWAiffh/k3W/GPhgYl
# t2WH/FQS4BcGpeWRb2Wi4seOUWb5lbgIuUKBORF0iiEiPNMLueuD3PAChl/h3WE2
# N1T8zsQg6UMrWtNRdby48xCI6zdD+26yNei3tOccrOWWullOehpBF5Z4vp8Xvq1n
# ysaSkGgAZNaKrb3F6et3V5Tq+gJ0DaLm/TGxATcTJ1mrHJOx+cHorSIeGKKzwa19
# uBuUbGALZx8Isus+3KiK7h2YcZ+AHU+qeUCLbKhU3l97Kg9E6/dvAMa+42/BXSmZ
# 9+F3WfagixcbNWGaZA1Pn8mPAgMBAAGjggFzMIIBbzAfBgNVHSUEGDAWBgorBgEE
# AYI3TAgBBggrBgEFBQcDAzAdBgNVHQ4EFgQUGxNB+9SPshuMPQ+xlMnFMiKVkDgw
# RQYDVR0RBD4wPKQ6MDgxHjAcBgNVBAsTFU1pY3Jvc29mdCBDb3Jwb3JhdGlvbjEW
# MBQGA1UEBRMNMjMwMDEyKzQ1NDEzNDAfBgNVHSMEGDAWgBRIbmTlUAXTgqoXNzci
# tW2oynUClTBUBgNVHR8ETTBLMEmgR6BFhkNodHRwOi8vd3d3Lm1pY3Jvc29mdC5j
# b20vcGtpb3BzL2NybC9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3JsMGEG
# CCsGAQUFBwEBBFUwUzBRBggrBgEFBQcwAoZFaHR0cDovL3d3dy5taWNyb3NvZnQu
# Y29tL3BraW9wcy9jZXJ0cy9NaWNDb2RTaWdQQ0EyMDExXzIwMTEtMDctMDguY3J0
# MAwGA1UdEwEB/wQCMAAwDQYJKoZIhvcNAQELBQADggIBADSrnbMt49ZGUc9KnW7S
# VkzITe55ApMwgxE8jl06lBkMZLd9QatyUt6g2/0RG0boaMHpWzypk6pGDLRD5y/P
# 6sj6fQYkrGihAw3W4ObLE3rrY8e5GPTrp/AlMFzsywHhD0+ETwgU8PuMvwQfB6ak
# 2ejWP0M1a1tkyAHfEMEGKd7RVPRmlLX+kPkJoFPz/uSlKxXi/acGH1qISQc0pkRt
# UE/ufrfpR+LlEOPg5aNZdAwIJAuDWInMeQM7kIoUTShSAJTzT58mrwVXgrfBbZnA
# NpsC/v8/amGL43MhTN0V2sWBHZNL7N0X9Z2qldu+jj8HdaNRGQyuru1W+IjNV914
# nk3qp9T/bZmy0elNYkCdNFjapARu6TZ0wwlEkvFW0HuzwtQ2gGDddGuhRFQRrdbU
# 68ifXf3dtvUDb0Nr+tnw9k0mV4s9jkTraDBaSJV0v1ixeR6WEBgGcc+uL/rHnci8
# 9cMcZqqcY8gGw0T1GpdDbWYLsYsqfPu5ZP4ga0kZa/ne7Bi3zu8XZ72kM893t5Ib
# Z96/2xp2Q+I6vIVfZJ7fh7vQ3OcLAZDvN+y6jNq3jtnQSYHuhX+Du074DXhQeVTB
# qTzBiuZPbnJhmI525u1GVoGemw0fqwk4cpeh3d1cDMN5eWlmqEdRwgaWozpj3a4I
# BzxVWkDJSJ4ZEq2odtK6eoYcMIIHejCCBWKgAwIBAgIKYQ6Q0gAAAAAAAzANBgkq
# hkiG9w0BAQsFADCBiDELMAkGA1UEBhMCVVMxEzARBgNVBAgTCldhc2hpbmd0b24x
# EDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jvc29mdCBDb3Jwb3JhdGlv
# bjEyMDAGA1UEAxMpTWljcm9zb2Z0IFJvb3QgQ2VydGlmaWNhdGUgQXV0aG9yaXR5
# IDIwMTEwHhcNMTEwNzA4MjA1OTA5WhcNMjYwNzA4MjEwOTA5WjB+MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSgwJgYDVQQDEx9NaWNyb3NvZnQg
# Q29kZSBTaWduaW5nIFBDQSAyMDExMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIIC
# CgKCAgEAq/D6chAcLq3YbqqCEE00uvK2WCGfQhsqa+laUKq4BjgaBEm6f8MMHt03
# a8YS2AvwOMKZBrDIOdUBFDFC04kNeWSHfpRgJGyvnkmc6Whe0t+bU7IKLMOv2akr
# rnoJr9eWWcpgGgXpZnboMlImEi/nqwhQz7NEt13YxC4Ddato88tt8zpcoRb0Rrrg
# OGSsbmQ1eKagYw8t00CT+OPeBw3VXHmlSSnnDb6gE3e+lD3v++MrWhAfTVYoonpy
# 4BI6t0le2O3tQ5GD2Xuye4Yb2T6xjF3oiU+EGvKhL1nkkDstrjNYxbc+/jLTswM9
# sbKvkjh+0p2ALPVOVpEhNSXDOW5kf1O6nA+tGSOEy/S6A4aN91/w0FK/jJSHvMAh
# dCVfGCi2zCcoOCWYOUo2z3yxkq4cI6epZuxhH2rhKEmdX4jiJV3TIUs+UsS1Vz8k
# A/DRelsv1SPjcF0PUUZ3s/gA4bysAoJf28AVs70b1FVL5zmhD+kjSbwYuER8ReTB
# w3J64HLnJN+/RpnF78IcV9uDjexNSTCnq47f7Fufr/zdsGbiwZeBe+3W7UvnSSmn
# Eyimp31ngOaKYnhfsi+E11ecXL93KCjx7W3DKI8sj0A3T8HhhUSJxAlMxdSlQy90
# lfdu+HggWCwTXWCVmj5PM4TasIgX3p5O9JawvEagbJjS4NaIjAsCAwEAAaOCAe0w
# ggHpMBAGCSsGAQQBgjcVAQQDAgEAMB0GA1UdDgQWBBRIbmTlUAXTgqoXNzcitW2o
# ynUClTAZBgkrBgEEAYI3FAIEDB4KAFMAdQBiAEMAQTALBgNVHQ8EBAMCAYYwDwYD
# VR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBRyLToCMZBDuRQFTuHqp8cx0SOJNDBa
# BgNVHR8EUzBRME+gTaBLhklodHRwOi8vY3JsLm1pY3Jvc29mdC5jb20vcGtpL2Ny
# bC9wcm9kdWN0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3JsMF4GCCsG
# AQUFBwEBBFIwUDBOBggrBgEFBQcwAoZCaHR0cDovL3d3dy5taWNyb3NvZnQuY29t
# L3BraS9jZXJ0cy9NaWNSb29DZXJBdXQyMDExXzIwMTFfMDNfMjIuY3J0MIGfBgNV
# HSAEgZcwgZQwgZEGCSsGAQQBgjcuAzCBgzA/BggrBgEFBQcCARYzaHR0cDovL3d3
# dy5taWNyb3NvZnQuY29tL3BraW9wcy9kb2NzL3ByaW1hcnljcHMuaHRtMEAGCCsG
# AQUFBwICMDQeMiAdAEwAZQBnAGEAbABfAHAAbwBsAGkAYwB5AF8AcwB0AGEAdABl
# AG0AZQBuAHQALiAdMA0GCSqGSIb3DQEBCwUAA4ICAQBn8oalmOBUeRou09h0ZyKb
# C5YR4WOSmUKWfdJ5DJDBZV8uLD74w3LRbYP+vj/oCso7v0epo/Np22O/IjWll11l
# hJB9i0ZQVdgMknzSGksc8zxCi1LQsP1r4z4HLimb5j0bpdS1HXeUOeLpZMlEPXh6
# I/MTfaaQdION9MsmAkYqwooQu6SpBQyb7Wj6aC6VoCo/KmtYSWMfCWluWpiW5IP0
# wI/zRive/DvQvTXvbiWu5a8n7dDd8w6vmSiXmE0OPQvyCInWH8MyGOLwxS3OW560
# STkKxgrCxq2u5bLZ2xWIUUVYODJxJxp/sfQn+N4sOiBpmLJZiWhub6e3dMNABQam
# ASooPoI/E01mC8CzTfXhj38cbxV9Rad25UAqZaPDXVJihsMdYzaXht/a8/jyFqGa
# J+HNpZfQ7l1jQeNbB5yHPgZ3BtEGsXUfFL5hYbXw3MYbBL7fQccOKO7eZS/sl/ah
# XJbYANahRr1Z85elCUtIEJmAH9AAKcWxm6U/RXceNcbSoqKfenoi+kiVH6v7RyOA
# 9Z74v2u3S5fi63V4GuzqN5l5GEv/1rMjaHXmr/r8i+sLgOppO6/8MO0ETI7f33Vt
# Y5E90Z1WTk+/gFcioXgRMiF670EKsT/7qMykXcGhiJtXcVZOSEXAQsmbdlsKgEhr
# /Xmfwb1tbWrJUnMTDXpQzTGCFVswghVXAgEBMIGVMH4xCzAJBgNVBAYTAlVTMRMw
# EQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVN
# aWNyb3NvZnQgQ29ycG9yYXRpb24xKDAmBgNVBAMTH01pY3Jvc29mdCBDb2RlIFNp
# Z25pbmcgUENBIDIwMTECEzMAAAFQyI+Wd95M8UcAAAAAAVAwDQYJYIZIAWUDBAIB
# BQCgga4wGQYJKoZIhvcNAQkDMQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEO
# MAwGCisGAQQBgjcCARUwLwYJKoZIhvcNAQkEMSIEIGWvQno/CJ986HIYh2jwdF43
# bks1r4mcSiYh3HTeXyN9MEIGCisGAQQBgjcCAQwxNDAyoBSAEgBNAGkAYwByAG8A
# cwBvAGYAdKEagBhodHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20wDQYJKoZIhvcNAQEB
# BQAEggEAllF4vsj6ZuFPQRPjJiiCnf6rJEuw8XwVqq72okHfpleHfKH+uMSbP0uX
# PghBSu7j6SsN9aH+I4QRUC5ysFibYElj2lWXv96OLIAZvjUAs9l71Eb0Hn35iJEW
# Dm3LFMRZmWKKuZsU9yBiWHoQ1BJUDGpSpYukM5rxjmjZ55SoD5Y+EUAKWSI7k4yc
# wqeHeonIxQPdkmwdFjH3qdMSyJ8+3dPJ3sqvaNeawrCz0y1Bz4RGdFzx1aOhu7NT
# fjdZj2Eb2Igzn8IDqI0lZF1qE95yl14i6ercnaqB1rJCSfQYhsfpMaYoIKvyHFKT
# 6gSJNa6qudWuQV2AJ8KyhkOTEoIbYKGCEuUwghLhBgorBgEEAYI3AwMBMYIS0TCC
# Es0GCSqGSIb3DQEHAqCCEr4wghK6AgEDMQ8wDQYJYIZIAWUDBAIBBQAwggFRBgsq
# hkiG9w0BCRABBKCCAUAEggE8MIIBOAIBAQYKKwYBBAGEWQoDATAxMA0GCWCGSAFl
# AwQCAQUABCDJGsfc55p9Nd3CbHIS6EOup8DYqM2MWo69IApv+tCRgQIGXUMmHhSG
# GBMyMDE5MDgwMzAzNDMyMS43ODZaMASAAgH0oIHQpIHNMIHKMQswCQYDVQQGEwJV
# UzELMAkGA1UECBMCV0ExEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEtMCsGA1UECxMkTWljcm9zb2Z0IElyZWxhbmQgT3Bl
# cmF0aW9ucyBMaW1pdGVkMSYwJAYDVQQLEx1UaGFsZXMgVFNTIEVTTjpBQjQxLTRC
# MjctRjAyNjElMCMGA1UEAxMcTWljcm9zb2Z0IFRpbWUtU3RhbXAgc2VydmljZaCC
# DjwwggTxMIID2aADAgECAhMzAAAA3IYTqAXYFYtHAAAAAADcMA0GCSqGSIb3DQEB
# CwUAMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQH
# EwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNV
# BAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMB4XDTE4MDgyMzIwMjY1
# NFoXDTE5MTEyMzIwMjY1NFowgcoxCzAJBgNVBAYTAlVTMQswCQYDVQQIEwJXQTEQ
# MA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9u
# MS0wKwYDVQQLEyRNaWNyb3NvZnQgSXJlbGFuZCBPcGVyYXRpb25zIExpbWl0ZWQx
# JjAkBgNVBAsTHVRoYWxlcyBUU1MgRVNOOkFCNDEtNEIyNy1GMDI2MSUwIwYDVQQD
# ExxNaWNyb3NvZnQgVGltZS1TdGFtcCBzZXJ2aWNlMIIBIjANBgkqhkiG9w0BAQEF
# AAOCAQ8AMIIBCgKCAQEAsPoXEjCNi8qS6Ww/tsTyq7CbdVKtpLF3QAbbQREFjmJ0
# 56Ggpzww68gwVJPKfxeXilueif7SmoYEUk/Ngm933VFzoPfypWRMGAps+z1lPlfG
# ZrgpsENMstKZzCz+oHjP9GV1vhebyF1yqmZ1EmwU08vyXFcVcb7AQQsxX66/3HZE
# OezWQNBBxUR97v5AC4+GbE3MzYR5O3uIXIxatf/QE4pG9d1RZLMtLA/469WC5A+i
# cvvI1dDJ41TKdcFp0c5adZThiT3XNlzO6bDoao2WhAXuGLxDAKOkQ1zLDBKqm9Nv
# krjJ4ePHr6p20budDC6A0Ch1MFUwjsy3dp8P0qvslwIDAQABo4IBGzCCARcwHQYD
# VR0OBBYEFDrVvNEDVZ0OHNlKXJJ+dLgqaZieMB8GA1UdIwQYMBaAFNVjOlyKMZDz
# Q3t8RhvFM2hahW1VMFYGA1UdHwRPME0wS6BJoEeGRWh0dHA6Ly9jcmwubWljcm9z
# b2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01pY1RpbVN0YVBDQV8yMDEwLTA3LTAx
# LmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYBBQUHMAKGPmh0dHA6Ly93d3cubWlj
# cm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljVGltU3RhUENBXzIwMTAtMDctMDEuY3J0
# MAwGA1UdEwEB/wQCMAAwEwYDVR0lBAwwCgYIKwYBBQUHAwgwDQYJKoZIhvcNAQEL
# BQADggEBABwtIuWSLIAHwv0ne3ECr5kwzT6+64FXiqqlzFn0H75BQJruK+hgQzFy
# +8CWQfMJnzCnNi1YuEmIg2YpeHtGFj3CHa+p/sXztD7AhKa+zT2z7bbo4vTrHnTC
# Xya85tRhLzkW3q35z3v5x10S1UnfyKnVxUc0GWe2tpa2ttV29HyQQRL3Gn0+r1+F
# 5YdrSqfNWgzUByszs2ZZUj7zLh7mMo/uknS3hdqz3lyEKV8lIHrrY5w4+qX5yote
# ErJpyS7MSo29Bh0tzX5ArWKvK2oLPHeWvTsq8RYjZ4VjjMB1foXnysntWnrCt9Ec
# Yu3GzHDUBN9+K/62glOhRjx3F1p4LvgwggZxMIIEWaADAgECAgphCYEqAAAAAAAC
# MA0GCSqGSIb3DQEBCwUAMIGIMQswCQYDVQQGEwJVUzETMBEGA1UECBMKV2FzaGlu
# Z3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwGA1UEChMVTWljcm9zb2Z0IENvcnBv
# cmF0aW9uMTIwMAYDVQQDEylNaWNyb3NvZnQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRo
# b3JpdHkgMjAxMDAeFw0xMDA3MDEyMTM2NTVaFw0yNTA3MDEyMTQ2NTVaMHwxCzAJ
# BgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25k
# MR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xJjAkBgNVBAMTHU1pY3Jv
# c29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A
# MIIBCgKCAQEAqR0NvHcRijog7PwTl/X6f2mUa3RUENWlCgCChfvtfGhLLF/Fw+Vh
# wna3PmYrW/AVUycEMR9BGxqVHc4JE458YTBZsTBED/FgiIRUQwzXTbg4CLNC3ZOs
# 1nMwVyaCo0UN0Or1R4HNvyRgMlhgRvJYR4YyhB50YWeRX4FUsc+TTJLBxKZd0WET
# bijGGvmGgLvfYfxGwScdJGcSchohiq9LZIlQYrFd/XcfPfBXday9ikJNQFHRD5wG
# Pmd/9WbAA5ZEfu/QS/1u5ZrKsajyeioKMfDaTgaRtogINeh4HLDpmc085y9Euqf0
# 3GS9pAHBIAmTeM38vMDJRF1eFpwBBU8iTQIDAQABo4IB5jCCAeIwEAYJKwYBBAGC
# NxUBBAMCAQAwHQYDVR0OBBYEFNVjOlyKMZDzQ3t8RhvFM2hahW1VMBkGCSsGAQQB
# gjcUAgQMHgoAUwB1AGIAQwBBMAsGA1UdDwQEAwIBhjAPBgNVHRMBAf8EBTADAQH/
# MB8GA1UdIwQYMBaAFNX2VsuP6KJcYmjRPZSQW9fOmhjEMFYGA1UdHwRPME0wS6BJ
# oEeGRWh0dHA6Ly9jcmwubWljcm9zb2Z0LmNvbS9wa2kvY3JsL3Byb2R1Y3RzL01p
# Y1Jvb0NlckF1dF8yMDEwLTA2LTIzLmNybDBaBggrBgEFBQcBAQROMEwwSgYIKwYB
# BQUHMAKGPmh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2kvY2VydHMvTWljUm9v
# Q2VyQXV0XzIwMTAtMDYtMjMuY3J0MIGgBgNVHSABAf8EgZUwgZIwgY8GCSsGAQQB
# gjcuAzCBgTA9BggrBgEFBQcCARYxaHR0cDovL3d3dy5taWNyb3NvZnQuY29tL1BL
# SS9kb2NzL0NQUy9kZWZhdWx0Lmh0bTBABggrBgEFBQcCAjA0HjIgHQBMAGUAZwBh
# AGwAXwBQAG8AbABpAGMAeQBfAFMAdABhAHQAZQBtAGUAbgB0AC4gHTANBgkqhkiG
# 9w0BAQsFAAOCAgEAB+aIUQ3ixuCYP4FxAz2do6Ehb7Prpsz1Mb7PBeKp/vpXbRkw
# s8LFZslq3/Xn8Hi9x6ieJeP5vO1rVFcIK1GCRBL7uVOMzPRgEop2zEBAQZvcXBf/
# XPleFzWYJFZLdO9CEMivv3/Gf/I3fVo/HPKZeUqRUgCvOA8X9S95gWXZqbVr5MfO
# 9sp6AG9LMEQkIjzP7QOllo9ZKby2/QThcJ8ySif9Va8v/rbljjO7Yl+a21dA6fHO
# mWaQjP9qYn/dxUoLkSbiOewZSnFjnXshbcOco6I8+n99lmqQeKZt0uGc+R38ONiU
# 9MalCpaGpL2eGq4EQoO4tYCbIjggtSXlZOz39L9+Y1klD3ouOVd2onGqBooPiRa6
# YacRy5rYDkeagMXQzafQ732D8OE7cQnfXXSYIghh2rBQHm+98eEA3+cxB6STOvdl
# R3jo+KhIq/fecn5ha293qYHLpwmsObvsxsvYgrRyzR30uIUBHoD7G4kqVDmyW9rI
# DVWZeodzOwjmmC3qjeAzLhIp9cAvVCch98isTtoouLGp25ayp0Kiyc8ZQU3ghvkq
# mqMRZjDTu3QyS99je/WZii8bxyGvWbWu3EQ8l1Bx16HSxVXjad5XwdHeMMD9zOZN
# +w2/XU/pnR4ZOC+8z1gFLu8NoFA12u8JJxzVs341Hgi62jbb01+P3nSISRKhggLO
# MIICNwIBATCB+KGB0KSBzTCByjELMAkGA1UEBhMCVVMxCzAJBgNVBAgTAldBMRAw
# DgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24x
# LTArBgNVBAsTJE1pY3Jvc29mdCBJcmVsYW5kIE9wZXJhdGlvbnMgTGltaXRlZDEm
# MCQGA1UECxMdVGhhbGVzIFRTUyBFU046QUI0MS00QjI3LUYwMjYxJTAjBgNVBAMT
# HE1pY3Jvc29mdCBUaW1lLVN0YW1wIHNlcnZpY2WiIwoBATAHBgUrDgMCGgMVAHgq
# 8wD2Onemka/iTyB8ERMyTtcdoIGDMIGApH4wfDELMAkGA1UEBhMCVVMxEzARBgNV
# BAgTCldhc2hpbmd0b24xEDAOBgNVBAcTB1JlZG1vbmQxHjAcBgNVBAoTFU1pY3Jv
# c29mdCBDb3Jwb3JhdGlvbjEmMCQGA1UEAxMdTWljcm9zb2Z0IFRpbWUtU3RhbXAg
# UENBIDIwMTAwDQYJKoZIhvcNAQEFBQACBQDg7vYYMCIYDzIwMTkwODAzMDE0OTEy
# WhgPMjAxOTA4MDQwMTQ5MTJaMHcwPQYKKwYBBAGEWQoEATEvMC0wCgIFAODu9hgC
# AQAwCgIBAAICJFoCAf8wBwIBAAICEb0wCgIFAODwR5gCAQAwNgYKKwYBBAGEWQoE
# AjEoMCYwDAYKKwYBBAGEWQoDAqAKMAgCAQACAwehIKEKMAgCAQACAwGGoDANBgkq
# hkiG9w0BAQUFAAOBgQACVMS0g/nERnrmKq1+RijkkgJK1bztRZtZs/bkcgdXKNkM
# zd4eExUZQ59MOQVvnb9kZO8MP/OIlSLj52wPE2R7vB+ghRg/4i+HdkgNxNkQJFRe
# Prbs1O0RgZWNoCuJscIqil3pZ54oB5km2f4ocoOXMU+8zR0LQqQ1xbnnnea3yDGC
# Aw0wggMJAgEBMIGTMHwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9u
# MRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRp
# b24xJjAkBgNVBAMTHU1pY3Jvc29mdCBUaW1lLVN0YW1wIFBDQSAyMDEwAhMzAAAA
# 3IYTqAXYFYtHAAAAAADcMA0GCWCGSAFlAwQCAQUAoIIBSjAaBgkqhkiG9w0BCQMx
# DQYLKoZIhvcNAQkQAQQwLwYJKoZIhvcNAQkEMSIEIH10SWcN5hv0mrYC9URXYXtw
# se1GFEr6EIuzz4Cyyya8MIH6BgsqhkiG9w0BCRACLzGB6jCB5zCB5DCBvQQgG8/u
# jUiuMWjU8VCLYM12DSowo3Js7CpNKIQ7Etnarl0wgZgwgYCkfjB8MQswCQYDVQQG
# EwJVUzETMBEGA1UECBMKV2FzaGluZ3RvbjEQMA4GA1UEBxMHUmVkbW9uZDEeMBwG
# A1UEChMVTWljcm9zb2Z0IENvcnBvcmF0aW9uMSYwJAYDVQQDEx1NaWNyb3NvZnQg
# VGltZS1TdGFtcCBQQ0EgMjAxMAITMwAAANyGE6gF2BWLRwAAAAAA3DAiBCDeg8qD
# M+TgwKmB/Kq6ngHMCui1JvC62R/8g47HvTJDfjANBgkqhkiG9w0BAQsFAASCAQAB
# lJ9k9mzTALtkCXhHOXr9aZxYzg9W+CbWBO0dh+Yi7mTtWh5JuTEEmTcaUxdSRkUA
# 914OgZPo0u4qBBKuq0oN8A9dq9H7vieUhAqEVE5GAx3oPVlcTldcxX42E7AsGIZH
# RCzsYqEr2eJhwRp0X6quikNAoN2quHXpjJ4NiBS8mhHMB9oNPeuaCqAlrUubfT8P
# 40NeHwJBA/K1ygSFGHeXA0+ANAjFn82J7GnEXWd2qvkq6QCuH1XaaskvVc1DyAc5
# DW1cJ3BUfuxcVY7vqa8wOtkhcq5HHFpYrRXokuwNrlj5RULkwV2J12C8e4ZKF+qB
# oas3LVQoCG+IyG3D7rAg
# SIG # End signature block
