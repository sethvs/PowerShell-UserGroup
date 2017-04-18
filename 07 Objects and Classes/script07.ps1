break

#objects

#service
sc.exe query type=service state=all

sc.exe query netlogon
sc.exe qc netlogon
sc.exe sdshow netlogon
sc.exe

Get-Service
Get-Service | where Status -eq 'Running'
Get-Service | where Status -eq 'Running' | where name -match ^a


#netstat
netstat

Get-NetTCPConnection 
Get-NetTCPConnection | sort RemotePort

#ipconfig

ipconfig
Get-NetIPConfiguration

ipconfig /all
Get-NetIPConfiguration -Detailed

$ipconfig = ipconfig
$ipconfig

$j = New-Object -TypeName System.Management.Automation.PSCustomObject
$j = New-Object -TypeName PSCustomObject
#$ipconfig | foreach -Process {
    switch -regex ($ipconfig)
    {
        '^\s*Connection-specific dns suffix.*:\s(.*$)' {$j | Add-Member -NotePropertyName 'DNS Suffix' -NotePropertyValue $Matches[1]}
        '^\s*IPv6 Address.*:\s(.*$)' {$j | Add-Member -NotePropertyName 'IPv6 Address' -NotePropertyValue $Matches[1]}
        '^\s*Temporary IPv6 Address.*:\s(.*$)' {
            if(!$j.'Temporary IPv6 Address')
            { 
                $j | Add-Member -NotePropertyName 'Temporary IPv6 Address' -NotePropertyValue @($Matches[1])
            }
            else
            {
                $j.'Temporary IPv6 Address' += $Matches[1]
            }
        }
        '^\s*Link-local IPv6 Address.*:\s(.*$)' {$j | Add-Member -NotePropertyName 'Link-local IPv6 Address' -NotePropertyValue $Matches[1]}
        '^\s*Subnet Mask.*:\s(.*$)' {$j | Add-Member -NotePropertyName 'Subnet Mask' -NotePropertyValue $Matches[1]}
        '^\s*Default Gateway.*:\s(.*$)' {$j | Add-Member -NotePropertyName 'Default Gateway' -NotePropertyValue $Matches[1]}
    }
#}
$j
$j.'Temporary IPv6 Address'
$j.'Temporary IPv6 Address'[-1]


switch ('a')
{
    a {"This is 'a'"}
    b {"This is 'b'"}
    c {"This is 'c'"}
    default {"Not 'a', 'b' or 'c'"}
}


$var = 'a'

if($var -eq 'a')
    {"This is 'a'"}
elseif($var -eq 'b')
    {"This is 'b'"}
elseif($var -eq 'c')
    {"This is 'c'"}
else
    {"Not 'a', 'b' or 'c'"}


#out objects

function f
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    Write-Host -Object ("Version: {0}" -f $cim.Caption) -ForegroundColor Green
    Write-Host -Object ("Build: {0}" -f $cim.Version) -ForegroundColor Green
    Write-Host -Object ("Name: {0}" -f $cim.CSName) -ForegroundColor Green
    Write-Host -Object ("Install Date: {0}" -f $cim.InstallDate) -ForegroundColor Green
}

f


function f
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    Write-Host -Object ("Version:      {0}" -f $cim.Caption) -ForegroundColor Green
    Write-Host -Object ("Build:        {0}" -f $cim.Version) -ForegroundColor Green
    Write-Host -Object ("Name:         {0}" -f $cim.CSName) -ForegroundColor Green
    Write-Host -Object ("Install Date: {0}" -f $cim.InstallDate) -ForegroundColor Green
}

f


function f
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    Write-Host -Object ("    Version:      {0}
    Build:        {1} 
    Name:         {2} 
    Install Date: {3}" -f $cim.Caption, $cim.Version, $cim.CSName, $cim.InstallDate) -ForegroundColor Green
}

f


function f
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    $out = "    Version:      {0}
    Build:        {1} 
    Name:         {2} 
    Install Date: {3}" -f $cim.Caption, $cim.Version, $cim.CSName, $cim.InstallDate

    Write-Host -Object $out -ForegroundColor Green
}

f

f | Format-Table

f | select version

f | Get-Member



function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    Write-Output $cim.Caption, $cim.Version, $cim.CSName, $cim.InstallDate
}

ff


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    $cim.Caption, $cim.Version, $cim.CSName, $cim.InstallDate
}

ff

function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    return $cim.Caption, $cim.Version, $cim.CSName, $cim.InstallDate
}

ff


ff | Get-Member

(ff | select -Skip 2 -First 1).tolower()
(ff | select -Skip 2 -First 1).toupper()


#http://msdn.microsoft.com/library/system.globalization.datetimeformatinfo.aspx
#https://msdn.microsoft.com/en-us/library/txafckwd(v=vs.110)

ff | select -Last 1 | Get-Date -Format g


#CustomObjects

#1

function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    $j = New-Object -TypeName PSCustomObject
    $j | Add-Member -MemberType NoteProperty -Name Version -Value $cim.Caption
    $j | Add-Member -MemberType NoteProperty -Name Build -Value $cim.Version
    $j | Add-Member -MemberType NoteProperty -Name Name -Value $cim.CSName
    $j | Add-Member -MemberType NoteProperty -Name InstallDate -Value $cim.InstallDate
    return $j
}

ff

ff | fl

ff | select version

ff | Get-Member

function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    $j = New-Object -TypeName PSCustomObject
    $j | Add-Member -MemberType NoteProperty -Name Version -Value $cim.Caption
    $j | Add-Member -MemberType NoteProperty -Name Build -Value $cim.Version
    $j | Add-Member -MemberType NoteProperty -Name Name -Value $cim.CSName
    $j | Add-Member -MemberType NoteProperty -Name InstallDate -Value $cim.InstallDate
    $j | Add-Member -TypeName PowerShell.VerySpecialObject
    return $j
}

ff | Get-Member

(ff).pstypenames


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    $j = New-Object -TypeName PSCustomObject
    $j | Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption
    $j | Add-Member -NotePropertyName Build -NotePropertyValue $cim.Version
    $j | Add-Member -NotePropertyName Name -NotePropertyValue $cim.CSName
    $j | Add-Member -NotePropertyName InstallDate -NotePropertyValue $cim.InstallDate
    $j | Add-Member -TypeName PowerShell.VerySpecialObject
    return $j
}

ff | Format-List
ff | Get-Member



function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem
    $j = New-Object -TypeName PSCustomObject
    $j | Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption
    $j | Add-Member -NotePropertyName Build -NotePropertyValue $cim.Version
    $j | Add-Member -NotePropertyName Name -NotePropertyValue $cim.CSName
    $j | Add-Member -NotePropertyName InstallDate -NotePropertyValue $cim.InstallDate -as [string]
    $j | Add-Member -TypeName PowerShell.VerySpecialObject
    return $j
}

ff | Get-Member

#2

$cim = Get-CimInstance -ClassName win32_operatingsystem
New-Object -TypeName PSCustomObject 
New-Object -TypeName PSCustomObject | Get-Member

New-Object -TypeName PSCustomObject | 
Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption

New-Object -TypeName PSCustomObject | 
Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption | Get-Member

New-Object -TypeName PSCustomObject | 
Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption -PassThru


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    $j = New-Object -TypeName PSCustomObject |
    Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption -PassThru |
    Add-Member -NotePropertyName Build -NotePropertyValue $cim.Version -PassThru |
    Add-Member -NotePropertyName Name -NotePropertyValue $cim.CSName -PassThru |
    Add-Member -NotePropertyName InstallDate -NotePropertyValue $cim.InstallDate -PassThru |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
    
    return $j
}

ff | Format-List


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    New-Object -TypeName PSCustomObject |
    Add-Member -NotePropertyName Version -NotePropertyValue $cim.Caption -PassThru |
    Add-Member -NotePropertyName Build -NotePropertyValue $cim.Version -PassThru |
    Add-Member -NotePropertyName Name -NotePropertyValue $cim.CSName -PassThru |
    Add-Member -NotePropertyName InstallDate -NotePropertyValue $cim.InstallDate -PassThru |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Format-List

#3

@{
Version = $cim.Caption
Build = $cim.Version
Name = $cim.CSName
InstallDate = $cim.InstallDate
}




function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    New-Object -TypeName PSCustomObject -Property @{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    } |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Format-List
ff | Get-Member





function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    $hash = @{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    }

    New-Object -TypeName PSCustomObject -Property $hash |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Format-List

#select


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    $cim | select -Property @{Name = 'Version'; Expression = {$cim.Caption}},
        @{Name = 'Build'; Expression = {$cim.Version}},
        @{Name = 'Name'; Expression = {$cim.CSName}},
        @{Name = 'InstallDate'; Expression = {$cim.InstallDate}}
}

ff | Format-List
ff | Get-Member

Get-CimInstance -ClassName win32_operatingsystem | Get-Member

ff | Get-Member

(ff).pstypenames

function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    $cim | select -Property @{Name = 'Version'; Expression = {$cim.Caption}},
        @{Name = 'Build'; Expression = {$cim.Version}},
        @{Name = 'Name'; Expression = {$cim.CSName}},
        @{Name = 'InstallDate'; Expression = {$cim.InstallDate}} |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Get-Member

(ff).pstypenames

#hash


function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

        $j = [PSCustomObject]@{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    }
    
    return $j

#    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Format-List
ff | Get-Member



function ff
{
    $cim = Get-CimInstance -ClassName win32_operatingsystem

    [PSCustomObject]@{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    } |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

ff | Format-List
ff | Get-Member
(ff).pstypenames


#scriptMethods


$cim = Get-CimInstance -ClassName win32_operatingsystem

$j = [PSCustomObject]@{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    }

$j  | Format-List
$j | Get-Member

$Script = {$this.Name = $this.Name.PadLeft($this.Name.Length+1,'"').PadRight($this.Name.Length+2,'"')}

$j | Add-Member -MemberType ScriptMethod -Name AddQuotes -Value $Script

$j | Get-Member
$j | Format-List
$j.AddQuotes()
$j | Format-List


#classes

function ff
{
    Param(
    $cim)

    [PSCustomObject]@{
        Version = $cim.Caption
        Build = $cim.Version
        Name = $cim.CSName
        InstallDate = $cim.InstallDate
    } |
    Add-Member -TypeName PowerShell.VerySpecialObject -PassThru
}

$cim = Get-CimInstance -ClassName Win32_OperatingSystem -ComputerName server

ff -cim $cim


class Operating_System
{
    [string]$Version
    [string]$Build
    [string]$Name
    [datetime]$InstallDate
}

[Operating_System]::new()

[Operating_System]::new() | Get-Member

([Operating_System]::new()).pstypenames


{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
    }

    $j = [Operating_System]::new()

    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
} 


$j | Format-List
$j | Get-Member
$j.pstypenames


#enum

{
    enum OSType
    {
        Workstation
        Server
    }
    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
        [OSType]$OSType
    }

    $j = [Operating_System]::new()

    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
    
} 


$j

{
    enum OSType
    {
        Workstation
        Server
    }
    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
        [OSType]$OSType
    }

    $j = [Operating_System]::new()

    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
    
    $j.OSType = 'MainFrame'
} 

#methods

{
    enum OSType
    {
        Workstation
        Server
    }
    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
        [OSType]$OSType

        [void]GoUpper()
        {
            $this.Name = $this.Name.ToUpper()
        }

        [void]GoLower()
        {
            $this.Name = $this.Name.ToLower()
        }

    }

    $j = [Operating_System]::new()

    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
    
    $j.OSType = 'Server'
} 

$j
$j | Get-Member

$j.GoLower()
$j

$j.GoUpper()
$j





{
    enum OSType
    {
        Workstation
        Server
    }
    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
        [OSType]$OSType

        [void]GoUpper()
        {
            $this.Name = $this.Name.ToUpper()
        }

        [void]GoLower()
        {
            $this.Name = $this.Name.ToLower()
        }

        [string]AddSymbols([char]$Symbol,[int]$Count)
        {
            $this.Name = $this.Name + [string]$Symbol * $Count
            return "Added!"

        }
    }

    $j = [Operating_System]::new()

    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
    
    $j.OSType = 'Server'
} 

$j
$j.AddSymbols()
$j.AddSymbols


$j.AddSymbols('!',15)
$j


#constructors

{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
    }

    [Operating_System]::new()
} 



{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_system()
        {
            $this.Version = 'Not Defined'
            $this.Build = 'Not Defined'
            $this.Name = 'Not Defined'
        }
    }

    [Operating_System]::new() | Format-List



    $cim = Get-CimInstance -ClassName win32_operatingsystem
    
    $j.Version = $cim.Caption
    $j.Build = $cim.Version
    $j.Name = $cim.CSName
    $j.InstallDate = $cim.InstallDate
    
    $j.OSType = 'Server'
} 



{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_system()
        {
            $this.Version = 'Not Defined'
            $this.Build = 'Not Defined'
            $this.Name = 'Not Defined'
        }

        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
    }

    [Operating_System]::new() | Format-List

    [Operating_System]::new

    $cim = Get-CimInstance -ClassName win32_operatingsystem

    [Operating_System]::new($cim.Caption,$cim.Version,$cim.CSName,$cim.InstallDate) | Format-List
    
} 




{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_system()
        {
            $this.Version = 'Not Defined'
            $this.Build = 'Not Defined'
            $this.Name = 'Not Defined'
        }

        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
        
        Operating_System([string]$Version,[string]$Caption,[string]$CSName,[datetime]$InstallDate)
        {

        }

    }
} 




{
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_system()
        {
            $this.Version = 'Not Defined'
            $this.Build = 'Not Defined'
            $this.Name = 'Not Defined'
        }

        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
        
        Operating_System([datetime]$InstallDate,[string]$Caption,[string]$Version,[string]$CSName)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
            Write-Host "This is another constructor" -ForegroundColor Green
        }

    }

    [Operating_System]::new

    [Operating_System]::new() | Format-List

    $cim = Get-CimInstance -ClassName win32_operatingsystem

    [Operating_System]::new($cim.Caption,$cim.Version,$cim.CSName,$cim.InstallDate) | Format-List

    [Operating_System]::new($cim.InstallDate,$cim.Caption,$cim.Version,$cim.CSName) | Format-List

    [Operating_System]::new($cim.Caption)
    
} 


#inheritance

{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
    }

    class Desktop : Operating_System
    {
        [string]$UserName
    }

    [Desktop]::new()

    [Desktop]::new() | Get-Member

    ([Desktop]::new()).pstypenames
}



{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate
    }

    class Desktop : Operating_System
    {
        [string]$UserName

        Desktop([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate,[string]$UserName)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
            $this.UserName = $UserName
        }
    
    }

    [Desktop]::new()
    [Desktop]::new($cim.Caption,$cim.Version,$cim.CSName,$cim.InstallDate,"SuperUser")
}




{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
    }

    class Desktop : Operating_System
    {
        [string]$UserName

        Desktop([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate,[string]$UserName) : 
        Base([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.UserName = $UserName
        }
    
    }

    [Desktop]::new()
    [Desktop]::new
    [Desktop]::new($cim.Caption,$cim.Version,$cim.CSName,$cim.InstallDate,"SuperUser")
}



{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
    }

    class Desktop : Operating_System
    {
        [string]$UserName

        Desktop()
        {

        }
        
        
        Desktop([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate,[string]$UserName) : 
        Base([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.UserName = $UserName
        }
    
    }

    [Desktop]::new()
    
}



{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_System()
        {

        }
        
        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
    }

    class Desktop : Operating_System
    {
        [string]$UserName

        Desktop()
        {

        }
        
        
        Desktop([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate,[string]$UserName) : 
        Base([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.UserName = $UserName
        }
    
    }

    [Desktop]::new()
    
}



{    
    class Operating_System
    {
        [string]$Version
        [string]$Build
        [string]$Name
        [datetime]$InstallDate

        Operating_System()
        {
            Write-Host "Creating Operating_System object" -ForegroundColor red
        }
        
        Operating_System([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.Version = $Caption
            $this.Build = $Version
            $this.Name = $CSName
            $this.InstallDate = $InstallDate
        }
    }

    class Desktop : Operating_System
    {
        [string]$UserName

        Desktop()
        {
            Write-Host "Creating Desktop object" -ForegroundColor Green
        }
        
        
        Desktop([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate,[string]$UserName) : 
        Base([string]$Caption,[string]$Version,[string]$CSName,[datetime]$InstallDate)
        {
            $this.UserName = $UserName
        }
    
    }

    [Desktop]::new()
    
}




#Блог
sergeyvasin.net

#Twitter
twitter.com/vsseth

#Группы
fb.com/inpowershell
vk.com/inpowershell

#GitHub
github.com/sethvs/PowerShell-UserGroup

