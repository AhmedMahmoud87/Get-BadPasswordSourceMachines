# Get-LockoutEvents.ps1
# PowerShell script to assist in troubleshooting account
# lockout issues. It can be used to collect Security Events
# from all DCs in a given forest or domain. It collects
# events like 4771, 4776 with error codes 0x18 and c000006a
# respectively.

# Author: Ahmed Fouad (ahfouad@microsoft.com)
# Version 1.6 - January 11, 2021

Param(
    [Parameter(Mandatory = $True)] $UserName,
    [Parameter(Mandatory = $True)] $DomainName

)

$RootDSE = Get-ADRootDSE -Server $DomainName 
$lockoutThreshold = (Get-ADObject $RootDSE.defaultNamingContext -Property lockoutThreshold).lockoutThreshold

#region initial checks

$Dcs = Get-ADDomainController -Filter * -Server $DomainName

[xml]$xmlfilter = "<QueryList> 
           <Query Id='0'> 
              <Select Path='Security'> 
                 *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and 
                 *[EventData[Data[@Name='status'] and (Data='0x18')]] 
                 and
                 *[System[(EventID='4771' or EventID='4768' or EventID='4769' )]]
              </Select> 
           </Query> 
<Query Id='1'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='substatus'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4625' )]] 
               </Select> 
           </Query> 
<Query Id='2'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
                  and
               *[System[(EventID='4740' or EventID='4767' )]] 
               </Select> 
           </Query> 
<Query Id='3'> 
              <Select Path='Security'> 
               *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 
               and  
               *[EventData[Data[@Name='Status'] and (Data='0xc000006a')]] 
                  and
               *[System[(EventID='4776' )]] 
               </Select> 
           </Query> 

</QueryList>"

try 
{
  Write-Host "Checking whether domain" $DomainName "exist or not" 
  if (Get-ADDomain $DomainName) 
   {
    Write-Host "Domain" $DomainName "already exist" -fore Green
   }

}


catch 
{

 write-host $_.Exception.Message -fore Red
 break 

}


try
{
   Write-Host "Checking whether AD user" $UserName "exist or not" 
   if (Get-ADUser -Identity $UserName -Server $DomainName) 
    {
     Write-Host "AD user" $UserName "already exist in" $DomainName "domain" -fore Green
    }
}

catch 
{

write-host  $_.Exception.Message -fore Red
break 


}

write-host "check whethe the current user has domain admin previlige or not" 

if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("$DomainName\Domain Admins") -and  (-not  ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole("Enterprise Admins") ) ) 
  {

    write-host "Sorry you don't have domain admin previliege to run this script" -fore Red
    Break
  }

Else 
  {
    write-host "User" $UserName "is member of $DomainName\Domain Admins" -fore Green
    
  }




$reportpath = read-host "Please enter the path of the report (leave it blank to use the default path)"

if ($reportpath)
    {
      $fullpath = $reportpath
      New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    }
Else 
    {
     $fullpath = (get-location).path
     New-Item -ItemType Directory -Path $fullpath\LockoutLogs -ErrorAction SilentlyContinue -InformationAction SilentlyContinue
    
    }

$CSVPath = $fullpath + "\LockoutLogs\Report.csv" 

$ExchangeServers = Get-ADGroup -Identity "Exchange Servers" |Get-ADGroupMember | ? {$_.objectClass -eq "Computer"}


$ExchangeServersIPv4 = @()

foreach ($ExchangeServer in $ExchangeServers ) 
{
   $ExchangeServersIPv4 += (Resolve-DnsName $ExchangeServer.name).IPAddress

}

#endregion 



function Get-Events 
{ 

Param ($DomainControllers, [string]$EnableNetLogon,$UserName)

$AllEvents = @()
$SourceMachines = @()
$servers = @()

#region Get events with monitoring mode

if ($EnableNetLogon -eq "True" )
{


Write-Host "Disable netlogon on all DCs" -ForegroundColor Green 

foreach ($dc in $DomainControllers)
{

Invoke-Command -ComputerName $dc -ScriptBlock { param ($EnableNetLogon)
if ($EnableNetLogon -eq "True" ) 
   {
   Nltest /DBFlag:0x0
   }

} -ArgumentList $EnableNetLogon
} 

Write-Host "Check domain controllers with bad passwords" -ForegroundColor Green 
foreach ($dc in $DomainControllers)
{

$serverName = $dc.HostName
$DomainControllersWithBadPWD = Invoke-Command -ComputerName $serverName -ScriptBlock  { param ($UserName)


 if ((Get-ADUser -Identity $UserName -Properties  badpwdcount).badpwdcount -gt 0 ) 
    {
       return "True" 
     
    }

} -ArgumentList $UserName

if ($DomainControllersWithBadPWD -eq "True")
{

  $servers += $serverName 

} 



}


foreach ($dc in $servers)
{



Write-Host "Checking audits on $dc" -ForegroundColor Green 

$AuditEnabled = Invoke-Command  -ComputerName $dc -ScriptBlock { param ($EnableNetLogon)   
   $i = 0  
   [string]$KerberosAuthenticationService = auditpol /get /subcategory:"Kerberos Authentication Service"
   [string]$CredentialValidation =  auditpol /get /subcategory:"Credential Validation" 
   [string]$Logon =  auditpol /get /subcategory:"Logon"
   [string]$AccountManagement =  auditpol /get /subcategory:"User Account Management"     
   if (!$KerberosAuthenticationService.Contains("Failure")) {Write-Host "Warning: Kerberos Authentication Service audit not enabled" -ForegroundColor DarkYellow; $i++ }
   if (!$CredentialValidation.Contains("Failure")) {Write-Host "Warning: Credential Validation audit not enabled" -ForegroundColor DarkYellow ; $i++ }
   if (!$Logon.Contains("Failure")) {Write-Host "Warning: Logon audit not enabled" -ForegroundColor DarkYellow ; $i++ } 
   if (!$AccountManagement.Contains("Failure")) {Write-Host "Warning: User Account Management audit not enabled" -ForegroundColor DarkYellow ; $i++ }
   if ($i -gt 0)
   { 
       Write-Host "Appropriate audits are not enabled. Please enable all required audits and then run the script again after repro the issue" -ForegroundColor Red
       Return "False"
           
   }

    if ($i -lt 1 )
     {
      Return "True"
     }
  
  } -ArgumentList  $EnableNetLogon

  if ($AuditEnabled -eq "False")
  {
   exit
  }


Write-Host "Checking connectivity to:" $dc 

$PingStatus = gwmi win32_pingStatus -Filter "Address = '$dc'"

if ($PingStatus.StatusCode -eq 0)
    {  
      Write-Host $dc  " is Online" -fore Green
      Write-Host "Collecting logs from:" $dc
      $Events = get-winevent -FilterXml $xmlfilter -ComputerName $dc -ErrorAction SilentlyContinue  
      foreach ($event in $events)
      {
       $eventxml = [xml]$event.ToXml()

       if ($event.Id -eq "4771")
         {
          $ipv4 = ($eventxml.Event.EventData.Data[6].'#text').Split(":")
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value  $ipv4[($ipv4.length -1 )]
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4771"
          $SourceMachines += $myObject
         } 
       if ($event.Id -eq "4776")
         {
          $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4776"
          $SourceMachines += $myObject
           
         }

       if ($event.Id -eq "4625")
         {
          $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value  $ipv4.IPAddress
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4625"
          $SourceMachines += $myObject
           
         }
      
      }
      write-host "Found"  $Events.count "Events on" $dc "for" $UserName -BackgroundColor Red
      $AllEvents += $Events
    }

Else 
   {
     Write-Host $dc  " is offline" -fore Red
   }

   if ( $EnableNetLogon -eq "True")
     {
      [string]$netlogon = $dc + "_Netlogon.log"
      Copy-Item -Path \\$dc\c$\Windows\Debug\netlogon.log -Destination "$fullpath\LockoutLogs\$netlogon" -Force -InformationAction SilentlyContinue
     }

$BadPWDInfo = Get-ADUser -Identity $UserName -Properties badpwdcount,badpasswordtime | select badpwdcount,badpasswordtime 
$RootDSE = Get-ADRootDSE -Server $DomainName 
$lockoutThreshold = (Get-ADObject $RootDSE.defaultNamingContext -Property lockoutThreshold).lockoutThreshold
$BadPWDInformation = @()
[string] $threshold = $lockoutThreshold
[string]$BadCount = $BadPWDInfo.badpwdcount
[string]$BadTime = [DateTime]::FromFileTime($user.badpasswordtime)
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name LockoutThreshold -Value $threshold
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name BadPasswordCount -Value $BadCount
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name BadPasswordtime -Value $BadTime

[string]$BadPWDInformationfile = $serverName + "_BadPWDInformation.txt"
$BadPWDInformation | out-file -FilePath "$fullpath\LockoutLogs\$BadPWDInformationfile"

}


}

#endregion 

#region get event wirthout monitoring mode



if ($EnableNetLogon -ne "True")

{

foreach ($dc in $DomainControllers)
{

$serverName = $dc.Name

Write-Host "Checking audits on $serverName" -ForegroundColor Green 

$AuditEnabled = Invoke-Command  -ComputerName $serverName -ScriptBlock { param ($EnableNetLogon)   
   $i = 0  
   [string]$KerberosAuthenticationService = auditpol /get /subcategory:"Kerberos Authentication Service"
   [string]$CredentialValidation =  auditpol /get /subcategory:"Credential Validation" 
   [string]$Logon =  auditpol /get /subcategory:"Logon"
   [string]$AccountManagement =  auditpol /get /subcategory:"User Account Management"     
   if (!$KerberosAuthenticationService.Contains("Failure")) {Write-Host "Warning: Kerberos Authentication Service audit not enabled" -ForegroundColor DarkYellow; $i++ }
   if (!$CredentialValidation.Contains("Failure")) {Write-Host "Warning: Credential Validation audit not enabled" -ForegroundColor DarkYellow ; $i++ }
   if (!$CredentialValidation.Contains("Failure")) {Write-Host "Warning: Logon audit not enabled" -ForegroundColor DarkYellow ; $i++ } 
   if (!$AccountManagement.Contains("Failure")) {Write-Host "Warning: User Account Management audit not enabled" -ForegroundColor DarkYellow ; $i++ } 
   if ($i -gt 0)
   { 
       Write-Host "Appropriate audits are not enabled. Please enable all required audits and then run the script again after repro the issue" -ForegroundColor Red
       Return "False"
           
   }

    if ($i -lt 1 )
     {
      Return "True"
     }
  
  } -ArgumentList  $EnableNetLogon

  if ($AuditEnabled -eq "False")
  {
   exit
  }


Write-Host "Checking connectivity to:" $serverName 

$PingStatus = gwmi win32_pingStatus -Filter "Address = '$serverName'"

if ($PingStatus.StatusCode -eq 0)
    {  
      Write-Host $serverName  " is Online" -fore Green
      Write-Host "Collecting logs from:" $serverName
      $Events = get-winevent -FilterXml $xmlfilter -ComputerName $serverName -ErrorAction SilentlyContinue  
      foreach ($event in $events)
      {
       $eventxml = [xml]$event.ToXml()

       if ($event.Id -eq "4771")
         {
          $ipv4 = ($eventxml.Event.EventData.Data[6].'#text').Split(":")
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value  $ipv4[($ipv4.length -1 )]
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4771"
          $SourceMachines += $myObject
         } 
       if ($event.Id -eq "4776")
         {
          $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value $ipv4.IPAddress
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4776"
          $SourceMachines += $myObject
           
         }

       if ($event.Id -eq "4625")
         {
          $ipv4 = Resolve-DnsName ($eventxml.Event.EventData.Data[2].'#text')
          $myObject = New-Object System.Object
          $myObject | Add-Member -type NoteProperty -name "Source Machine" -Value  $ipv4.IPAddress
          $myObject | Add-Member -type NoteProperty -name "Event ID" -Value "4625"
          $SourceMachines += $myObject
           
         }
      
      }
      write-host "Found"  $Events.count "Events on" $serverName "for" $UserName -BackgroundColor Red
      $AllEvents += $Events
    }

Else 
   {
     Write-Host $serverName  " is offline" -fore Red
   }

Write-Host "Check whether netlogon enabled or not" -ForegroundColor Green 

  $netlogonenabled =  Invoke-Command -ComputerName $serverName -ScriptBlock { 
     $DBFlag = (Get-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters -Name DBflag | select DBflag).DBFlag 
     if ($DBFlag -eq "0x2080ffff")
       {
         return "True"
       
       }


   }

if ($netlogonenabled -eq "True" )

{
 Write-Host "Netlogon enabled: Collectng netlogon.log file" -ForegroundColor Green 
[string]$netlogon = $serverName + "_Netlogon.log"
Copy-Item -Path \\$serverName\c$\Windows\Debug\netlogon.log -Destination "$fullpath\LockoutLogs\$netlogon" -Force -InformationAction SilentlyContinue

}

$BadPWDInfo = Get-ADUser -Identity $UserName -Properties badpwdcount,badpasswordtime | select badpwdcount,badpasswordtime 
$RootDSE = Get-ADRootDSE -Server $DomainName 
$lockoutThreshold = (Get-ADObject $RootDSE.defaultNamingContext -Property lockoutThreshold).lockoutThreshold
$BadPWDInformation = New-Object -TypeName PSObject
[string] $threshold = $lockoutThreshold
[string]$BadTime = [DateTime]::FromFileTime($user.badpasswordtime)
[string]$BadCount = $BadPWDInfo.badpwdcount
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name LockoutThreshold -Value $threshold
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name BadPasswordCount -Value $BadCount
$BadPWDInformation | Add-Member -MemberType NoteProperty -Name BadPasswordtime -Value $BadTime

[string]$BadPWDInformationfile = $serverName + "_BadPWDInformation.txt"
$BadPWDInformation | out-file -FilePath "$fullpath\LockoutLogs\$BadPWDInformationfile"
$BadPWDInformation


}

}



#endregion 

#region save the report 

if ($AllEvents -ne 0)

   { 
     $AllEvents | select MachineName,TimeCreated,ProviderName,Id,@{n='Message';e={$_.Message -replace '\s+', " "}} | Export-Csv -Path  $CSVPath -NoTypeInformation
   }


Write-Host  $AllEvents.count "events found on all domain controllers `n" -BackgroundColor red


if ($SourceMachines.Count -gt 0 )
  {

    Write-Host "Summary of source machines for the bad password `n" -BackgroundColor Green -ForegroundColor Red
    $SourceMachines | Group-Object "Source Machine","Event ID"  -NoElement   | Sort-Object -Property Count -Descending

    $ExchangeServersIncluded = Compare-Object -ReferenceObject $SourceMachines."Source Machine"  -DifferenceObject $ExchangeServersIPv4  -IncludeEqual -ExcludeDifferent

     if ($ExchangeServersIncluded.InputObject.Length -gt 0 ) 
       { 
         Write-Host "`n Below Exchange Servers included in bad password source machines list `n" -BackgroundColor Green -ForegroundColor Red
         $ExchangeServersIncluded.InputObject

         $ExportExchangeLogs = read-host "`nDo you want to export IIS logs from mentioned Exchange servers (Yes/No)" 
         while ("yes","no","y","n" -notcontains $ExportExchangeLogs )
         {
            $ExportExchangeLogs = read-host "`nDo you want to export IIS logs from mentioned Exchange servers (Yes/No)"
         } 
         
          if ($ExportExchangeLogs -eq "yes" -or $ExportExchangeLogs -eq "y")

            {
              foreach ($ip in $ExchangeServersIncluded.InputObject)
                {
                  New-Item -ItemType Directory -Path "$fullpath\Exchange_$ip" -InformationAction SilentlyContinue -ErrorAction SilentlyContinue
                 
                  Copy-Item -Path \\$ip\c$\inetpub\logs\LogFiles -Destination "$fullpath\LockoutLogs\Exchange_$ip" -Recurse -Force -InformationAction SilentlyContinue
                 
                }
            
            }

       }     
  }     


exit 

#endregion 

}





#region Monitor lockout

function monitor-event
{

Param ($DomainControllers)

Write-Host "Check whether the current DC is the PDCEmulator or not" -ForegroundColor Green
$currentDCName = [System.Net.Dns]::GetHostByName($env:computerName).hostname
$PDCEmulator = (Get-ADDomain | select PDCEmulator).PDCEmulator
if ($currentDCName -ne $PDCEmulator)
{
 Write-Host "This DC is not the PDCEmulator. Please run the sript from the PDCEmulator domain controller." -ForegroundColor Red

 exit

}

foreach ($dc in $DomainControllers)
{
$serverName = $dc.HostName
Write-Host "Checking audits on $serverName" -ForegroundColor Green 

$AuditEnabled = Invoke-Command  -ComputerName $serverName -ScriptBlock { param ($EnableNetLogon)   
   $i = 0  
   [string]$KerberosAuthenticationService = auditpol /get /subcategory:"Kerberos Authentication Service"
   [string]$CredentialValidation =  auditpol /get /subcategory:"Credential Validation" 
   [string]$Logon =  auditpol /get /subcategory:"Logon"
   [string]$AccountManagement =  auditpol /get /subcategory:"User Account Management"     
   if (!$KerberosAuthenticationService.Contains("Failure")) {Write-Host "Warning: Kerberos Authentication Service audit not enabled" -ForegroundColor DarkYellow; $i++ }
   if (!$CredentialValidation.Contains("Failure")) {Write-Host "Warning: Credential Validation audit not enabled" -ForegroundColor DarkYellow ; $i++ }
   if (!$Logon.Contains("Failure")) {Write-Host "Warning: Logon audit not enabled" -ForegroundColor DarkYellow ; $i++ } 
   if (!$AccountManagement.Contains("Failure")) {Write-Host "Warning: User Account Management audit not enabled" -ForegroundColor DarkYellow ; $i++ }
   if ($i -gt 0)
   { 
       Write-Host "Appropriate audits are not enabled. Please enable all required audits and then run the script again after repro the issue" -ForegroundColor Red
       Return "False"
           
   }

    if ($i -lt 1 )
     {
      Return "True"
     }
  
  } -ArgumentList  $EnableNetLogon

  if ($AuditEnabled -eq "False")
  {
   exit
  }

}

Write-Host "Enabling Netlogon Debug on all $serverName" -ForegroundColor Green 
foreach ($dc in $DomainControllers)
 {
   
   $serverName = $dc.HostName
   
   Invoke-Command -ComputerName $serverName -ScriptBlock {Nltest /DBFlag:2080FFFF}

 }



$time = 120000
$Trigger = "False"

$xml =  "<QueryList>
  <Query Id='0' Path='Security'>
    <Select Path='Security'>*[System[(EventID=4740) and TimeCreated[timediff(@SystemTime) &lt;= $time]]]
    and 
    *[EventData[Data[@Name='TargetUserName'] and (Data='$username')]] 

    </Select>
  </Query>
</QueryList>"


while ( $Trigger -eq "False") 
  {
    Write-host "Monitoring Account lockout event for $username"  -ForegroundColor Green  
    Start-Sleep -Seconds 60 
    $Events = Get-WinEvent -FilterXml $xml -ErrorAction SilentlyContinue 
    if ($Events.Properties.Count -gt 0) 
     {
      Get-Events -DomainControllers $Dcs -EnableNetLogon "True" -UserName $username
     }

  } 
  exit 
} 
#endregion

#region main script



$Monitor = read-host "`nDo you want to wait for next lockout (Yes/No)" 
         while ("yes","no","y","n" -notcontains $Monitor )
         {
            $Monitor = read-host "`nDo you want to wait for next lockout (Yes/No)"
         } 
         
          if ($Monitor -eq "yes" -or $Monitor -eq "y")
          {
             
             monitor-event -DomainControllers $dcs 
          
          }

          if ($Monitor -eq "No" -or $Monitor -eq "n")

          {
                          
             Get-Events -DomainControllers $dcs -EnableNetLogon "False" -UserName $UserName
              
          }

#endregion 







 



