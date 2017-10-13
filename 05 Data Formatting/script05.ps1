###########################################################################
break

#format-
    #Format-List Format-Table Format-Wide Format-Custom
Get-Command Format-*
Get-Command Format-* -Module Microsoft.PowerShell.Utility -CommandType Cmdlet

#default format
Get-Service
Get-NetIPAddress

Get-Service
Get-Service | Format-List
Get-NetIPAddress
Get-NetIPAddress | Format-Table

#default format example
#Tcpip.Format.ps1xml
Get-NetRoute
Get-NetRoute | Format-List

#reverse TableControl and ListControl in Tcpip.Format.ps1xml for MSFT_NetRoute

Update-FormatData
Get-NetRoute
Get-NetRoute | Format-Table


#format-table
Get-Service
Get-Process

#Tcpip.Format.ps1xml
#<TypeName>Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPAddress</TypeName>
Get-NetIPAddress | Format-Table
Get-NetIPAddress | Format-Table -AutoSize

Get-NetIPAddress | Format-Table
Get-NetIPAddress | Format-Table -Wrap

Get-NetIPAddress | Format-Table -HideTableHeaders
#Get-NetIPAddress | Format-Table -HideTableHeaders | Out-File c:\csv.csv 

#expand
$p1 = Get-Process -Name p*
$p2 = Get-Process -Name p*
$p1
$p2
$p = @($p1, $p2)

$p[0]
$p[1]
$p[0][2]
$p[1][2]

$p.Count
$p[0].Count
$p[1].Count

$p | Format-Table
$p | Format-Table -Expand EnumOnly
$p | Format-Table -Expand CoreOnly
cls
$p | Format-Table -Expand Both


#view
Get-Process
#DotNetTypes.format.ps1xml
#<TypeName>System.Diagnostics.Process
Get-Process | Format-Table -View asd

<#
Get-FormatData -TypeName System.Diagnostics.Process | Export-FormatData -Path 'c:\process.format.ps1xml' -IncludeScriptBlock

$format = Get-FormatData -TypeName System.Diagnostics.Process
$format.TypeName
$format.FormatViewDefinition
$format.FormatViewDefinition[0]
$format.FormatViewDefinition[0].Control
$format.FormatViewDefinition[0].Control.Headers
$format.FormatViewDefinition[0].Control.Rows

Get-Service | gm
Get-FormatData -TypeName System.ServiceProcess.ServiceController | Export-FormatData -Path Service.format.ps1xml
#>


Get-Process | Format-Table -View process

Get-Process | Format-Table -View Priority
#DotNetTypes.format.ps1xml
#<TypeName>System.Diagnostics.Process</TypeName>

Get-Process | Sort-Object -Property PriorityClass |  Format-Table -View Priority
cls
Get-Process | Sort-Object -Property BasePriority |  Format-Table -View Priority

#SortProperties
Get-Process | Select-Object -First 1 | Format-List -Property * 
Get-Process | Select-Object -First 1 | Format-List -Property PriorityClass, BasePriority

Get-Process
Get-Process | Sort-Object -Property ID
Get-Process | Sort-Object -Property ID | Format-List -Property *

$process = Get-Process | Select-Object -First 1 
$process | Format-List -Property *
$process | Get-Member
$process | Get-Member -Force
$process.psobject
$process.psobject.Properties
$process.psobject.Properties | Select-Object -Property Name, Value
$process.psobject.Properties | Sort-Object -Property Name |  Select-Object -Property Name, Value




Get-Process | Format-Table -View StartTime
Get-Process | Sort-Object -Property StartTime | Format-Table -View StartTime
Get-Process | Sort-Object -Property StartTime -ErrorAction SilentlyContinue | Format-Table -View StartTime


#includeUserName
Get-Process -IncludeUserName

Get-Process -IncludeUserName | Format-Table -Wrap
Get-Process -IncludeUserName | Format-Table -AutoSize

Get-Process -IncludeUserName | Get-Member

#<TypeName>System.Diagnostics.Process#IncludeUserName</TypeName>

$processes = Get-Process -IncludeUserName

$process = $processes[0]
$process.psobject.TypeNames
$process.pstypenames

$process | Add-Member -TypeName 'System.Diagnostics.Process#UserGroup'
$process.pstypenames

$process

$process | Add-Member -TypeName 'Anything_that_come_accross'
$process.pstypenames

$process

#property
Get-Process | fl *
Get-Process | Format-Table -Property ProcessName, Handles, ID
Get-Process | Format-Table -Property h*

#list_or_table
Get-Process | Select-Object -Property ProcessName, Handles, ID
Get-Process | Select-Object -Property ProcessName, Handles, ID, Description
Get-Process | Select-Object -Property ProcessName, Handles, ID, Description, Path


Get-Process | Format-Table -Property @{Name = "Process Name"; Expression = {$_.ProcessName}}, 
                                     @{Label = "Number of Handles"; Expression = {$PSItem.Handles}},
                                     @{Label = "Process ID"; Expression = {$_.ID}}

{Get-Process -Name p*}
$command = {Get-Process -Name p*}
$command 
& $command

#https://msdn.microsoft.com/en-us/library/txafckwd(v=vs.110)
#Composite Formatting

#Standard Numeric Format Strings
Get-Process | Format-Table -Property @{Name = "Process Name"; Expression = {$_.ProcessName};}, 
                                     @{Label = "Number of Handles"; Expression = {$PSItem.Handles}; FormatString = "C"},
                                     @{Label = "Process ID"; Expression = {$_.ID}; FormatString = "D6"}

Get-Process | Format-Table -Property @{Name = "Process Name"; Expression = {$_.ProcessName};}, 
                                     @{Label = "Number of Handles"; Expression = {$PSItem.Handles}; FormatString = "F2"},
                                     @{Label = "Process ID"; Expression = {$_.ID}; FormatString = "N3"}




<#
$ps = ps
$ps[0].id.ToString("N3")
$ps[0].id.ToString("N3",[CultureInfo]"RU-RU")
$ps[0].id.ToString
Get-Culture | gm
Get-UICulture | gm 


[CultureInfo]"ru-ru"
[CultureInfo]'ru-ru'


"{0,-30} {1,10:F2} {2,20:N0}" -f "ProcessName", "CPU", "WorkingSet(bytes)"
"{0,-30} {1,10:F2} {2,20:N0}" -f "-----------", "---", "-----------------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0,[CultureInfo]'ru-ru'}" -f $item.ProcessName, $item.cpu, $item.ws
}

    "{0,-30} {1,10:F2} {2,20:N0}" -f $item.ProcessName, $item.cpu, $item.ws
#>



#groupby
Get-Service | Format-Table -GroupBy Status
Get-Service | Sort-Object -Property Status | Format-Table -GroupBy Status

Get-Service | Sort-Object -Property Name | Format-Table -GroupBy @{Name = "Letter"; Expression = {$_.name.Substring(0,1)}}


#out
#Get-Service | Sort-Object -Property Name | Format-Table -GroupBy @{Name = "Letter"; Expression = {$_.name.Substring(0,1)}} | Get-Member
#Get-Service | Sort-Object -Property Name | Format-Table -GroupBy @{Name = "Letter"; Expression = {$_.name.Substring(0,1)}} | Out-File -FilePath c:\out.txt

<#
Get-Service | Select-Object -Property name,status,starttype,canstop
Get-Service | Select-Object -Property name,status,starttype,canstop | Where-Object {$_.status -eq 'Running'} 
Get-Service | Select-Object -Property name,status,starttype,canstop | Get-Member
#>


#not_the_objects
Get-Service 
Get-Service | Where-Object {$_.status -eq 'Running'}
Get-Service | Where-Object {$_.status -eq 'Running'} | Format-Table -Property name,status,starttype,canstop

Get-Service | Format-Table -Property name,status,starttype,canstop
Get-Service | Format-Table -Property name,status,starttype,canstop | Where-Object {$_.status -eq 'Running'} 

Get-Service | Where-Object {$_.status -eq 'Running'} | Get-Member
Get-Service | Format-Table -Property name,status,starttype,canstop | Get-Member
Get-Service | Format-Table -Property name,status,starttype,canstop | Out-File -FilePath c:\out.txt

#Format-List

Get-NetIPAddress 
Get-NetIPAddress | Format-List

#expand
$p | Format-List 
$p | Format-List -Expand EnumOnly
$p | Format-List -Expand CoreOnly
$p | Format-List -Expand Both

#view
#C:\Windows\System32\WindowsPowerShell\v1.0\DotNetTypes.format.ps1xml
#<TypeName>System.ServiceProcess.ServiceController</TypeName>
Get-Service | Format-List -View asd
Get-Service | Format-List -View System.ServiceProcess.ServiceController
Get-Service | Format-List

Get-Service | Get-Member
Get-FormatData -TypeName System.ServiceProcess.ServiceController
$ServiceFormat = Get-FormatData -TypeName System.ServiceProcess.ServiceController
$ServiceFormat.FormatViewDefinition
$ServiceFormat.FormatViewDefinition[0].Control
$ServiceFormat.FormatViewDefinition[0].Control.Headers
$ServiceFormat.FormatViewDefinition[0].Control.Rows

$ServiceFormat.FormatViewDefinition[1].Control
$ServiceFormat.FormatViewDefinition[1].Control.Entries
$ServiceFormat.FormatViewDefinition[1].Control.Entries.Items


#Create Service_UG.format.ps1xml
#from C:\Windows\System32\WindowsPowerShell\v1.0\DotNetTypes.format.ps1xml
#<TypeName>System.ServiceProcess.ServiceController</TypeName>

#View Service_UG
#List Properties: Name, DisplayName, Status

Update-FormatData -AppendPath C:\Windows\System32\WindowsPowerShell\v1.0\Service_UG.format.ps1xml
Get-FormatData -TypeName System.ServiceProcess.ServiceController


Get-Service
Get-Service | Format-List -View asd
Get-Service | Format-List 
Get-Service | Format-List -View Service_UG


Update-FormatData -PrependPath C:\Windows\System32\WindowsPowerShell\v1.0\Service_UG.format.ps1xml
Get-FormatData -TypeName System.ServiceProcess.ServiceController

Get-Service | Format-List -View asd
Get-Service | Format-List -View Service_UG
Get-Service | Format-List 
Get-Service

Update-FormatData -AppendPath C:\Windows\System32\WindowsPowerShell\v1.0\Service_UG.format.ps1xml
Get-FormatData -TypeName System.ServiceProcess.ServiceController


Get-FormatData -TypeName System.ServiceProcess.ServiceController | Export-FormatData -Path c:\Service.format.ps1xml


#allegedly no views
Get-NetIPAddress | Format-List 
Get-NetIPAddress | Format-List -View asd
Get-NetIPAddress | gm

Get-FormatData -TypeName Microsoft.Management.Infrastructure.CimInstance#ROOT/StandardCimv2/MSFT_NetIPAddress
Get-NetIPAddress | Format-List -View DefaultView

Get-NetIPAddress | Format-List -View TableView
Get-NetIPAddress | Format-Table -View TableView

#property

Get-NetIPAddress
Get-NetIPAddress | Format-List -Property IPAddress,InterfaceIndex,InterfaceAlias

Get-NetIPAddress | Format-Table -Property *
Get-NetIPAddress | Format-List -Property *
Get-NetIPAddress | fl *

<#
Get-Process | Format-Table -Property *
Get-Process | Format-List -Property *
#>

#groupBy
Get-Process | Format-List -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}}

Get-Process | Sort-Object -Property cpu | Format-List -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}}
Get-Process | Sort-Object -Property cpu | Format-List -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}} -Property Name,CPU

Get-Process | 
Sort-Object -Property cpu | 
Format-List -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}} `
-Property Name, @{Name = 'Handles'; Expression = {$_.Handles}; FormatString = "N0"}, @{Name = 'CPU'; Expression = {$_.cpu}; FormatString = "F2"}


#format-wide
Get-Process | Format-Wide
Get-Process | Format-Wide -AutoSize
Get-Process | Format-Wide -Column 7

Get-Service | Format-Wide -AutoSize
Get-Service | Format-Wide -AutoSize -Property DisplayName

#<TypeName>System.Diagnostics.Process</TypeName>
#C:\Windows\System32\WindowsPowerShell\v1.0\DotNetTypes.format.ps1xml
Get-Process | Format-Wide -View asd
Get-Process | Format-Wide -View process

#why
#<TypeName>System.ServiceProcess.ServiceController</TypeName>
Get-Service | Format-Wide -AutoSize


#format-custom
Get-NetIPAddress | Format-Custom

Get-Item c:\Windows | Format-Custom
Get-Item C:\Windows | Format-Custom -Depth 1

#C:\Windows\System32\WindowsPowerShell\v1.0\FileSystem.format.ps1xml
#<Name>FileSystemTypes-GroupingFormat</Name>
Get-Item C:\Users
Get-Item C:\Users | fl *
Get-ChildItem C:\Users -Recurse






<#

#Get-NetRoute | Format-Table        - add Interface Alias

#format-list
gsv
ps

#format-wide
ps


#format-custom
Get-Date | Format-Custom
h | fc


#PSStandardMembers
    #PSDefaultDisplayPropertySet
    #Format-List

Get-Process | Format-List
Get-Process | Format-Custom

#C:\Windows\System32\WindowsPowerShell\v1.0\DotNetTypes.format.ps1xml
#<TypeName>System.Diagnostics.Process</TypeName>

#C:\Windows\System32\WindowsPowerShell\v1.0\types.ps1xml
#<Name>System.Diagnostics.Process</Name>

$ps = Get-Process
$ps[0].PSStandardMembers
$ps[0].PSStandardMembers.DefaultDisplayPropertySet
$ps[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames




#PSDefaultDisplayProperty
#Format-Wide
ls -Directory | fw
#C:\Windows\System32\WindowsPowerShell\v1.0\typesv3.ps1xml
#    <Name>System.IO.DirectoryInfo</Name>
# File Example - Get-NetRoute | fw (DestinationPrefix)

#>




#PSStandardMembers
#PSDefaultDisplayPropertySet
#Format-List
Get-Process | Format-List
Get-Process | Format-Custom

Get-Process | Format-List -View asd
#DotNetTypes.format.ps1xml
#<TypeName>System.Diagnostics.Process</TypeName>


Get-FormatData -TypeName System.Diagnostics.Process
Get-FormatData -TypeName System.Diagnostics.Process | select -ExpandProperty FormatViewDefinition


#C:\Windows\System32\WindowsPowerShell\v1.0\types.ps1xml
#    <Name>System.Diagnostics.Process</Name>

Get-Process | Get-Member -MemberType Properties


#PSConfiguration and PSResources
Get-Process | Get-Member
Get-Process | Get-Member -MemberType PropertySet

Get-Process | Get-Member -Name PSConfiguration
Get-Process | Get-Member -Name PSResources

(Get-Process | Get-Member -Name PSResources).Definition

$ps = Get-Process
$ps[0].PSConfiguration
$ps[0].PSConfiguration.ReferencedPropertyNames
$ps[0].PSResources
$ps[0].PSResources.ReferencedPropertyNames

Get-Process | Select-Object -Property PSConfiguration
Get-Process | Select-Object -Property PSResources

Get-Process | Format-List -Property PSConfiguration
Get-Process | Format-List -Property PSResources

#return

Get-Process | Get-Member
Get-Process | Get-Member -Force

Get-Process | Get-Member -Force -MemberType MemberSet

$ps = Get-Process
$ps[0].PSStandardMembers
$ps[0].PSStandardMembers.DefaultDisplayPropertySet
$ps[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames

Get-Process | Format-List
Get-Process | Format-Custom



#C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Types.ps1xml
$dns = Resolve-DnsName -Name microsoft.com
$dns

$dns[0] | Get-Member
$dns[0] | Get-Member -MemberType MemberSet
$dns[0] | Get-Member -Force -MemberType MemberSet
$dns[0] | Get-Member -Name PSStandardMembers
$dns[0] | Get-Member -Force -Name PSStandardMembers


$dns[0].PSStandardMembers

$dns[0].PSStandardMembers | Get-Member


$dns[0].PSStandardMembers.DefaultDisplayPropertySet
$dns[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames

$dns[0].PSStandardMembers.DefaultDisplayProperty

$dns[0].PSStandardMembers.DefaultKeyPropertySet
$dns[0].PSStandardMembers.DefaultKeyPropertySet.ReferencedPropertyNames


#when view exist
$dns | Format-List 
$dns[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames

#C:\Windows\System32\WindowsPowerShell\v1.0\Modules\DnsClient\DnsCmdlets.Format.ps1xml
#<Name>Microsoft.DnsClient.Commands.DnsRecord_A_AAAA</Name>
Get-FormatData -TypeName Microsoft.DnsClient.Commands.DnsRecord_A
$format = Get-FormatData -TypeName Microsoft.DnsClient.Commands.DnsRecord_A
$format[0]
$format[0].FormatViewDefinition


$dns | Format-Custom
$dns[0].PSStandardMembers.DefaultDisplayPropertySet.ReferencedPropertyNames



#PSDefaultDisplayProperty
$dns[0].PSStandardMembers.DefaultDisplayProperty
$dns | Format-Wide
$dns[0] | fl *
$dns | gm

$dns[0] | Update-TypeData -MemberName PrimaryDomainSuffix -MemberType AliasProperty -Value Name
$dns[0] | fl *
$dns | gm
$dns | fl *

$dns | Format-Wide

#PSDefaultKeyPropertySet
$dns[0].PSStandardMembers.DefaultKeyPropertySet
$dns[0].PSStandardMembers.DefaultKeyPropertySet.ReferencedPropertyNames

$dns
$dns | Sort-Object
$dns | Group-Object




#volcanos

$volcanos = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\05\Volcanos.csv' 
$volcanos
$volcanos[0] 
$volcanos[0].pstypenames
$volcanos[0] | Get-Member



<#
[hashtable[]]$hash = $null

foreach($vol in $volcanos)
{
    $hash += @{Name = $($vol.Name); Zone = $($vol.Zone); Location = $($vol.location); Notes = $($vol.notes); 'Years ago' = [int]$($vol.'years ago'); 'Volume(km3)' = [int]$($vol.'Volume(km3)'); Classification = $($vol.Classification)}
}

$hash[0]
$hash[0].'Years ago' | gm
$hash[0].'Volume(km3)' | gm


#$volcanos = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\04\Volcanos.csv' -Header 'Name','Zone','Location','Notes','Years ago','Volume(km3)','Classification'


[psobject[]]$vols = $null

foreach($ha in $hash)
{
    $vols += New-Object -TypeName PSObject -Property $ha
}

$vols
$vols | gm
#>

[psobject[]]$vols = $null

foreach($vol in $volcanos)
{
    $vols += New-Object -TypeName PSObject -Property `
        @{Name = $vol.Name; 
        Zone = $vol.Zone; 
        Location = $vol.location; 
        Notes = $vol.notes; 
        'Years ago' = [int]$vol.'years ago'; 
        'Volume(km3)' = [int]$vol.'Volume(km3)'; 
        Classification = $vol.Classification}
}

$vols
$vols[0]
$vols | gm
$vols[0].pstypenames


#or

$vols = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\05\Volcanos.csv' | 
    Select-Object -Property `
        @{Name = 'Name'; Expression = {$PSItem.Name}},
        @{Name = 'Zone'; Expression = {$PSItem.Zone}},
        @{Name = 'Location'; Expression = {$PSItem.location}},
        @{Name = 'Notes'; Expression = {$PSItem.notes}},
        @{Name = 'Years ago'; Expression = {[int]$PSItem.'years ago'}},
        @{Name = 'Volume(km3)'; Expression = {[int]$PSItem.'Volume(km3)'}},
        @{Name = 'Classification'; Expression = {$PSItem.Classification}}

$vols
$vols[0]
$vols[0].pstypenames
$vols | gm



$vols | Add-Member -TypeName 'UserGroup.Volcanos'

$vols | Get-Member
$vols[0].pstypenames
$vols[11].pstypenames


$vols | Format-Table
$vols | Format-List

#create volcanos.types.ps1xml from DnsCmdlets.Types.ps1xml Microsoft.DnsClient.Commands.DnsRecord_A

#<Name>UserGroup.Volcanos</Name>
#Add DefaultDisplayPropertySet
#Name,Location,'Years ago','Volume(km3)'

Update-TypeData -PrependPath 'C:\Windows\System32\WindowsPowerShell\v1.0\volcanos.types.ps1xml'

$vols | Format-List
$vols | Format-Table
$vols | Format-Custom

#wide
$vols | Format-Wide
$vols | Select-Object -First 1
$vols | gm


#Add DefaultDisplayProperty
#Location
Update-TypeData -PrependPath 'C:\Windows\System32\WindowsPowerShell\v1.0\volcanos.types.ps1xml'
$vols | Format-Wide



#sort
$vols
$vols | sort 
$vols | sort | ft *

#$vols[0].psobject
#$vols[0].psobject.Properties

$vols | Group-Object

#Add DefaultKeyPropertySet
#Name,Volume(km3)

Update-TypeData -PrependPath 'C:\Windows\System32\WindowsPowerShell\v1.0\volcanos.types.ps1xml'


$vols | Sort-Object
$vols | gm


$vols | Group-Object
$vols | Group-Object | ft -AutoSize
$vols | Group-Object | sort name | ft -AutoSize

$vols | Group-Object -Property Name


#wide priority

#$vols | Export-Csv -Path c:\volcanos2.csv
#$vols | select Location,Zone,Name, Notes,'Years ago','Volume(km3)',Classification | Export-Csv -Path c:\volcanos2.csv

<#
$volcanos2 = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\04\volcanos2.csv'
$volcanos2 | Format-Wide
$volcanos2 | fl
#>

$volcanos3 = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\05\volcanos3.csv'
$volcanos3 | fl
$volcanos3 | fw
$volcanos3 | gm

#Name, notName, Namee, not
#Volume(km3) -> ID, notID, IDd

$volcanos3 = Import-Csv -Path 'C:\Users\seth\Desktop\PowerShell UG\05\volcanos3.csv'
$volcanos3 | fw
$volcanos3 | gm
$volcanos3[0].psobject.Properties | select name,value

Get-Service | Format-Wide -AutoSize


###order of properties in object - later
$vols | fl *

[psobject[]]$vols2 = $null

foreach($vol in $volcanos)
{
    $vols2 += New-Object -TypeName PSObject -Property `
        @{not = $vol.Name; 
        Zone = $vol.Zone; 
        Location = $vol.location; 
        Notes = $vol.notes; 
        'Years ago' = [int]$vol.'years ago'; 
        'Volume(km3)' = [int]$vol.'Volume(km3)'; 
        Classification = $vol.Classification}
}

$vols2 | fw
$vols2 | fl
$vols2 | gm

$vols2[0]
$vols2[0].psobject
$vols2[0].psobject.Properties
gm -i $vols2[0].psobject.Properties

[psobject[]]$vols2 = $null
foreach($vol in $volcanos)
{
    $h = [ordered]@{not = $vol.Name; Zone = $vol.Zone; Location = $vol.location; Notes = $vol.notes; 'Years ago' = [int]$vol.'years ago'; 'Volume(km3)' = [int]$vol.'Volume(km3)'; Classification = $vol.Classification}
    $vols2 += New-Object -TypeName PSObject -Property $h
}

$vols2 | fw
$vols2 | fl



<#

$ps | ft -Property @{Name="|||Header|||";Expression = {$_.id};FormatString="F3"}
$ps | fl -Property @{Name="|||Header|||";Expression = {$_.id};FormatString="c"}


ps | fl -GroupBy @{name = "ID!";Expression = {$_.id};FormatString ="F3"}

ps | fl -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}}

ps | sort cpu | fl -GroupBy @{name = "CPU Load";Expression = {if($_.cpu -lt 1){"Low"} elseif($_.cpu -lt 100){"Medium"} else{"High"}}} -Property Name,CPU


ls c:\file.txt | fc -Depth 1

#>


#f
#digits

$ps = Get-Process
$ps | Format-Table -Property ProcessName,cpu,ws

foreach ($item in $ps)
{
    "{0} {1} {2}" -f $item.ProcessName, $item.cpu, $item.ws
}

foreach ($item in $ps)
{
    "{0,-30} {1,15} {2,20}" -f $item.ProcessName, $item.cpu, $item.ws
}

foreach ($item in $ps)
{
    "{0,-30} {1,15:F2} {2,20:N0}" -f $item.ProcessName, $item.cpu, $item.ws
}


"{0,-30} {1,15:F2} {2,20:N0}" -f "ProcessName", "CPU", "WorkingSet(bytes)"
"{0,-30} {1,15:F2} {2,20:N0}" -f "-----------", "---", "-----------------"
foreach ($item in $ps)
{
    "{0,-30} {1,15:F2} {2,20:N0}" -f $item.ProcessName, $item.cpu, $item.ws
}



#dates

"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}

#short_date_pattern - d
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30:d}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}


#long_data_pattern - D
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30:D}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}


"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30:dd.MM.yyyy (ddd) - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}

#non-formatting_symbols
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30: dd.MM.yyyy 0_0 - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}

"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30: Date and Time is: dd.MM.yyyy 0_0 - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}

"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30: 'Date and Time is:' dd.MM.yyyy 0_0 - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}

#escape_symbol
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30:dd.MM.yyyy (\d\d\d) - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}


"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "ProcessName", "CPU", "WorkingSet(bytes)", "Start Time"
"{0,-30} {1,10:F2} {2,20:N0} {3,30}" -f "-----------", "---", "-----------------", "----------"
foreach ($item in $ps)
{
    "{0,-30} {1,10:F2} {2,20:N0} {3,30:dd.MM.yyyy (\ddd) - HH:mm:ss}" -f $item.ProcessName, $item.cpu, $item.ws, $item.StartTime
}



#custom_number_formatting
$number = 12543748
"{0:00000}" -f $number
"{0:000000000000000000000000000000000000}" -f $number
"{0:#}" -f $number
"{0:####################################}" -f $number


"{0:#,#}" -f $number

"{0:#,#.#}" -f $number
"{0:#,#.00}" -f $number


#culture
$number = 12543

"{0:N2}" -f $number
"{0:c2}" -f $number

$Culture = Get-Culture
$Culture
$Culture | Get-Member
$Culture | fl *
$Culture.NumberFormat

$Culture.NumberFormat.CurrencyDecimalSeparator = '!'
"{0:c2}" -f $number

$Culture.NumberFormat.CurrencySymbol = '??????'

$Culture.NumberFormat
"{0:c2}" -f $number

"{0:N2}" -f $number
$Culture.NumberFormat.NumberDecimalSeparator = ','
$Culture.NumberFormat.NumberGroupSeparator = '.'
"{0:N2}" -f $number


#ToString()
$number.ToString
$number.ToString()

$number.ToString("N2")
$number.ToString("C2")

$number.ToString("C2","ru-ru")
$number.ToString("C2",[CultureInfo]"ru-ru")

$number.ToString("N2",[CultureInfo]"ru-ru")


$ru = [CultureInfo]"ru-ru"
$ru.NumberFormat


[int]"₽"

"₽" | Get-Member

[char]"₽"

[char]"₽" -as [int]

[int][char]"₽"

[char]8381

$Culture.NumberFormat.CurrencySymbol = [char]8381
$Culture.NumberFormat

"{0:c2}" -f $number




#Блог
sergeyvasin.net

#Twitter
twitter.com/vsseth

#Группы
fb.com/inpowershell
vk.com/inpowershell

#GitHub
github.com/sethvs/PowerShell-UserGroup






####################################################################

