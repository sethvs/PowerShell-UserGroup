#09

break

Get-Command -Module ActiveDirectory
 
Get-Command -Module ADDSDeployment

dsa
dssite
domain
dsac
adsiedit

#OUs

New-ADOrganizationalUnit -Name 'allusers' -Path 'dc=domain,dc=com' 

New-ADOrganizationalUnit -Name 'allusers' -Path 'dc=domain,dc=int' 

Get-ADOrganizationalUnit -Filter {name -eq 'allusers'}

Get-ADOrganizationalUnit -LDAPFilter '(name=allusers)'

Get-ADOrganizationalUnit -Identity 

<#
-- A Distinguished Name
-- A GUID (objectGUID)
#>

Get-ADOrganizationalUnit -Identity 'OU=allusers,DC=domain,DC=int'
Get-ADOrganizationalUnit -Identity 'b1d36d01-df54-4c1f-bd9e-fe8892bf89b5'

$allusersou = Get-ADOrganizationalUnit -Identity 'ou=allusers,dc=domain,dc=int'

#users

$pass = Read-Host -Prompt "Password: " -AsSecureString 

$pass = ConvertTo-SecureString -String 'Pa$$w0rd' -AsPlainText -Force

New-ADUser -Name 'Ivanov Ivan' -GivenName 'Ivan' -Surname 'Ivanov' -UserPrincipalName ivanov@domain.com -SamAccountName ivanov -AccountPassword $pass -Path $allusersou.DistinguishedName -Enabled $true
New-ADUser -Name 'Petrov Petr' -GivenName Petr -Surname Petrov -UserPrincipalName petrov@domain.com -SamAccountName petrov -AccountPassword $pass -Path $allusersou.DistinguishedName -Enabled $true -Title 'operator' -Department 'sales'
New-ADUser -Name 'Sidorov Sidor' -GivenName Sidor -Surname Sidorov -UserPrincipalName sidorov@domain.com -SamAccountName sidorov -AccountPassword $pass -Path $allusersou.DistinguishedName -Enabled $true -Title 'Chief of Staff' -Department 'administration'

New-ADUser someuser


#adsi

[ADSI]"ldap://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"

[ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user = [ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user
$user | Format-List -Property *
$user.Title

$user.Title = 'staff'
$user.Title 
$user.setInfo()

$user = [ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user.Title

$user.Put('Title', 'manager')
$user.Title
$user.SetInfo()

$user = [ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user.Title



#user
Get-ADUser

Get-ADUser -Filter *

Get-ADUser -Filter {Title -like "o*"}

Get-ADUser -Filter 'Title -like "o*"'

Get-ADUser -Filter {Title -like "o*" -and Department -eq 'Sales'}
Get-ADUser -Filter {Title -like "o*" -and Department -eq 'Sales' -and Enabled -eq $true}

Get-ADUser -Filter {(Title -like "o*" -and Department -eq 'Sales') -or (Title -like "chief*" -and Department -like "adm*")}

Get-ADUser -LDAPFilter '(&(objectCategory=person)(Title=o*))'

Get-ADObject -LDAPFilter '(&(objectCategory=person)(Title=o*))'

Get-ADObject -LDAPFilter '(objectClass=user)'

[ADSI]"LDAP://CN=Petrov Petr,OU=allusers,DC=domain,DC=int"
[ADSI]"LDAP://CN=Petrov Petr,OU=allusers,DC=domain,DC=int" | fl distinguishedName,objectClass,objectCategory

$server = [ADSI]"LDAP://CN=server,OU=Domain Controllers,DC=domain,DC=int"
$server.objectClass
$server.objectCategory


Get-ADUser -Identity

<#
-- A Distinguished Name
-- A GUID (objectGUID)
-- A Security Identifier (objectSid)
-- A SAM Account Name (sAMAccountName)
#>

Get-ADUser -Identity ivanov
Get-ADUser -Identity 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int'
Get-ADUser -Identity 'S-1-5-21-1665931338-2339104762-3393818886-1112'
Get-ADUser -Identity 'be2afbd4-1f7e-4442-ad49-08b960630de0'

#searchbase and searchscope

$allusersou
$allusersou.DistinguishedName

Get-ADUser -Filter *

Get-ADUser -Filter * -SearchBase 'OU=allusers,DC=domain,DC=int'

Get-ADUser -Filter * -SearchBase 'OU=allusers,DC=domain,DC=int' -SearchScope 

<#
Base
OneLevel
Subtree
#>

New-ADOrganizationalUnit -Name someusers -Path 'ou=allusers,dc=domain,dc=int'
$someusersou = Get-ADOrganizationalUnit -Identity 'ou=someusers,ou=allusers,dc=domain,dc=int'

New-ADUser -Name 'Alexandrov Alexandr' -GivenName Alexandr -Surname Alexandrov -UserPrincipalName alexandrov@domain.com -SamAccountName alexandrov -AccountPassword $pass -Path $someusersou.DistinguishedName -Enabled $true

Get-ADObject -Filter * -SearchBase 'OU=allusers,DC=domain,DC=int' -SearchScope Base

Get-ADObject -Filter * -SearchBase 'OU=allusers,DC=domain,DC=int' -SearchScope OneLevel

Get-ADObject -Filter * -SearchBase 'OU=allusers,DC=domain,DC=int' -SearchScope Subtree


#properties

Get-ADUser ivanov

Get-ADUser ivanov -Properties *
Get-ADUser ivanov -Properties SamAccountName, title, department


#l, sn
Set-ADUser -Identity ivanov -City 'Seattle' -Department 'strategic research'

Get-ADUser ivanov -Properties City, Department

$user = [ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user | fl *

Get-ADUser ivanov -Properties l, City, sn


Set-ADUser -Identity ivanov -City 'Seattle'

Set-ADUser ivanov -Replace @{l='Houston'}

Get-ADUser ivanov -Properties l, City, sn


#set

Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName | select name, distinguishedName
Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName -SearchScope OneLevel | select name, distinguishedName

Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName -SearchScope OneLevel | Set-ADUser -City Austin -WhatIf

Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName -SearchScope OneLevel | Set-ADUser -City Austin

Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName -SearchScope OneLevel | select name, distinguishedName, City

Get-ADUser -Filter * -SearchBase $allusersou.DistinguishedName -SearchScope OneLevel -Properties City | select name, distinguishedName, City


Set-ADUser -

Set-ADUser ivanov -Initials 'AB'
Set-ADUser ivanov -Comment 'TheComment'


<#
Remove
Add
Replace
Clear
#>

Set-ADUser ivanov -Add @{Comment='TheComment1'}
Get-ADUser ivanov -Properties Comment

Set-ADUser ivanov -Remove @{Comment='TheComment1'}
Get-ADUser ivanov -Properties Comment

Set-ADUser ivanov -Add @{Comment='TheComment1'}
Set-ADUser ivanov -Add @{Comment='TheComment2'}

Set-ADUser ivanov -Replace @{Comment='TheComment3'}
Get-ADUser ivanov -Properties Comment

Set-ADUser ivanov -Clear Comment
Get-ADUser ivanov -Properties Comment



#computer

New-ADOrganizationalUnit -Name 'comps' -Path 'dc=domain,dc=int'
$compsou = Get-ADOrganizationalUnit -Identity 'ou=comps,dc=domain,dc=int'

New-ADComputer -Name comp1 -OperatingSystem 'Windows 10 Pro' -Path $compsou.DistinguishedName
New-ADComputer -Name comp2 -OperatingSystem 'Windows 10 Pro' -Path $compsou.DistinguishedName
New-ADComputer -Name comp3 -OperatingSystem 'Windows 10 Pro' -Path $compsou.DistinguishedName

Get-ADComputer -Filter {OperatingSystem -like "*10*"}

Get-ADComputer -LDAPFilter '(&(objectCategory=computer)(OperatingSystem=*10*))'

Get-ADComputer -Identity comp1
Get-ADComputer -Identity 'CN=comp1,OU=comps,DC=domain,DC=int'
Get-ADComputer -Identity 'S-1-5-21-1665931338-2339104762-3393818886-1117'
Get-ADComputer -Identity '55d6af2f-6a3b-404c-abd6-81c32739f67e'


##set

Set-ADComputer comp1 -Description 'Do not turn off'
Get-ADComputer comp1 -Properties description

##delegation
Get-ADComputer comp1 -Properties *

Get-ADComputer comp1 -Properties msDS-AllowedToDelegateTo | % msDS-AllowedToDelegateTo

Set-ADComputer comp1 -Remove @{'msDS-AllowedToDelegateTo' = 'http/server'}

Get-ADComputer comp1 -Properties msDS-AllowedToDelegateTo | % msDS-AllowedToDelegateTo

Set-ADComputer comp1 -Add @{'msDS-AllowedToDelegateTo' = 'http/server'}

Get-ADComputer comp1 -Properties msDS-AllowedToDelegateTo | % msDS-AllowedToDelegateTo



#groups

New-ADOrganizationalUnit -Name 'groups' -Path 'dc=domain,dc=int' 
$groupsou = Get-ADOrganizationalUnit -Identity 'ou=groups,dc=domain,dc=int'

New-ADGroup -Name UserGroup -GroupScope DomainLocal -Path $groupsou.DistinguishedName


Get-ADGroup -Filter {groupCategory -eq 'Security' -and GroupScope -eq 'DomainLocal' -and Name -like "UserGr*"}

Get-ADGroup -LDAPFilter '(&(objectCategory=group)(name=UserGr*))'


Get-ADGroup -Identity UserGroup
Get-ADGroup -Identity 'CN=UserGroup,OU=groups,DC=domain,DC=int'
Get-ADGroup -Identity 'S-1-5-21-1665931338-2339104762-3393818886-1116'
Get-ADGroup -Identity '67d893c2-3889-48af-bc16-737c0902cab2'

Get-ADGroup UserGroup -Properties *

Get-ADGroupMember -Identity UserGroup

Add-ADGroupMember -Identity UserGroup -Members ivanov,petrov,sidorov

Get-ADGroupMember -Identity UserGroup


#nested

New-ADGroup -Name TopLevelGroup -GroupScope DomainLocal -Path $groupsou.DistinguishedName
New-ADGroup -Name SecondLevelGroup -GroupScope DomainLocal -Path $groupsou.DistinguishedName
New-ADGroup -Name ThirdLevelGroup -GroupScope DomainLocal -Path $groupsou.DistinguishedName

Add-ADGroupMember -Identity TopLevelGroup -Members SecondLevelGroup
Add-ADGroupMember -Identity SecondLevelGroup -Members ThirdLevelGroup
Add-ADGroupMember -Identity ThirdLevelGroup -Members UserGroup


Get-ADGroupMember -Identity ThirdLevelGroup
Get-ADGroupMember -Identity ThirdLevelGroup -Recursive #noncontainers
Get-ADGroupMember -Identity ThirdLevelGroup -Recursive | select name,distinguishedName

Get-ADGroupMember -Identity SecondLevelGroup
Get-ADGroupMember -Identity SecondLevelGroup -Recursive
Get-ADGroupMember -Identity SecondLevelGroup -Recursive | select name,distinguishedName

Get-ADGroupMember -Identity TopLevelGroup
Get-ADGroupMember -Identity TopLevelGroup -Recursive
Get-ADGroupMember -Identity TopLevelGroup -Recursive | select name,distinguishedName


#users_in_groups
Get-ADGroup UserGroup -Properties *
Get-ADGroup UserGroup -Properties Members
Get-ADGroup UserGroup -Properties Members | % Members

Get-ADUser ivanov
Get-ADUser ivanov -Properties *
Get-ADUser ivanov -Properties Memberof
Get-ADUser ivanov -Properties Memberof | % Memberof

#ADPrincipal
Get-ADPrincipalGroupMembership -Identity ivanov

Get-ADPrincipalGroupMembership -Identity ivanov | select name,distinguishedName

Add-ADPrincipalGroupMembership -Identity ivanov -MemberOf TopLevelGroup
Get-ADPrincipalGroupMembership -Identity ivanov | select name,distinguishedName

Remove-ADPrincipalGroupMembership -Identity ivanov -MemberOf TopLevelGroup
Get-ADPrincipalGroupMembership -Identity ivanov | select name,distinguishedName


#ADAuthorization
Get-ADAccountAuthorizationGroup -Identity ivanov
Get-ADAccountAuthorizationGroup -Identity ivanov | Select-Object -Property Name

Get-ADAccountAuthorizationGroup -Identity ivanov | Select-Object -Property Name,distinguishedName | sort distinguishedName

#https://msdn.microsoft.com/en-us/library/cc980032.aspx
<#
S-1: Indicates a revision or version 1 SID.
5: SECURITY_NT_AUTHORITY, indicates it's a Windows specific SID.
21: SECURITY_NT_NON_UNIQUE, indicates a domain id will follow.
#>

Get-ADAccountAuthorizationGroup -Identity ivanov | ? SID -like "S-1-5-21*"
Get-ADAccountAuthorizationGroup -Identity ivanov | ? SID -like "S-1-5-21*" | % name

Get-ADAccountAuthorizationGroup -Identity ivanov | ? {($_.SID -like "S-1-5-21*") -and ($_.SID -notlike "*-513")} | % name


Get-ADDomain
$domain = Get-ADDomain

Get-ADAccountAuthorizationGroup -Identity ivanov | ? SID -like "$($domain.domainSID)*"
Get-ADAccountAuthorizationGroup -Identity ivanov | ? SID -like "$($domain.domainSID)*" | % name

Get-ADAccountAuthorizationGroup -Identity ivanov | ? {($_.SID -like "$($domain.domainSID)*") -and ($_.SID -notlike "$($domain.domainSID)" + "-513")} | % name


"$domain.domainSID"

$domain.ToString()

"$($domain.domainSID)"



Get-ADAccountAuthorizationGroup -Identity ivanov | ? objectClass

Get-ADAccountAuthorizationGroup -Identity ivanov | ? objectClass | % name

Get-ADAccountAuthorizationGroup -Identity ivanov | ? distinguishedName | % name


##recursiveMatch

Get-ADUser -Filter {memberof -eq "UserGroup"}

Get-ADUser ivanov -Properties memberof

Get-ADUser -Filter {memberof -eq "CN=UserGroup,OU=groups,DC=domain,DC=int"}

Get-ADUser -Filter {memberof -eq "CN=UserGroup,OU=groups,DC=domain,DC=int" -and SamAccountName -eq 'ivanov'}

Get-ADUser -Filter {memberof -eq "CN=UserGroup,OU=groups,DC=domain,DC=int"} -SearchBase 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int'


Get-ADUser -Filter {memberof -eq "CN=TopLevelGroup,OU=groups,DC=domain,DC=int"}

Get-ADUser -Filter {memberof -RecursiveMatch "CN=TopLevelGroup,OU=groups,DC=domain,DC=int"}


Get-ADUser -Filter {memberof -RecursiveMatch "CN=TopLevelGroup,OU=groups,DC=domain,DC=int" -and SamAccountName -eq 'ivanov'}

Get-ADUser -Filter {memberof -RecursiveMatch "CN=TopLevelGroup,OU=groups,DC=domain,DC=int"} -SearchBase 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int'



#LDAP_MATCHING_RULE_IN_CHAIN

Get-ADUser -LDAPFilter '(memberof:1.2.840.113556.1.4.1941:=CN=TopLevelGroup,OU=groups,DC=domain,DC=int)'

Get-ADUser -LDAPFilter '(&(memberof:1.2.840.113556.1.4.1941:=CN=TopLevelGroup,OU=groups,DC=domain,DC=int)(SamAccountName=ivanov))'

Get-ADUser -LDAPFilter '(memberof:1.2.840.113556.1.4.1941:=CN=TopLevelGroup,OU=groups,DC=domain,DC=int)' -SearchBase 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int'


#bitmasks

Get-ADUser ivanov

Get-ADUser -Filter {samaccountname -eq 'ivanov' -and enabled -eq $true}

$user = [ADSI]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$user.Enabled

#userAccountControl
#https://msdn.microsoft.com/en-us/library/ms680832(v=vs.85).aspx

Get-ADUser ivanov -Properties UserAccountControl

#0x00000200 ADS_UF_NORMAL_ACCOUNT

#enabled
#0x00000002 ADS_UF_ACCOUNTDISABLE

Get-ADUser ivanov | Disable-ADAccount
Get-ADUser ivanov -Properties UserAccountControl

Get-ADUser ivanov | Enable-ADAccount
Get-ADUser ivanov -Properties UserAccountControl


$user = Get-ADUser ivanov -Properties UserAccountControl
$user.UserAccountControl -band 2

Get-ADUser ivanov | Disable-ADAccount
$user = Get-ADUser ivanov -Properties UserAccountControl
$user.UserAccountControl -band 2

Get-ADUser ivanov | Enable-ADAccount

#disable
$user = Get-ADUser ivanov -Properties UserAccountControl
$user.UserAccountControl

$disable = $user.UserAccountControl -bor 2
$disable
Set-ADUser ivanov -Replace @{UserAccountControl = $disable}

Get-ADUser ivanov


#enable

$user = Get-ADUser ivanov -Properties UserAccountControl
$user.UserAccountControl

$enable = $user.UserAccountControl -band (-bnot 2)
$enable
Set-ADUser ivanov -Replace @{UserAccountControl = $enable}

Get-ADUser ivanov


#ldapdisable

[int32]$ADS_UF_ACCOUNTDISABLE = 2

$adsiuser = [adsi]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$adsiuser
$adsiuser.userAccountControl

$disabled = $adsiuser.UserAccountControl -bor $ADS_UF_ACCOUNTDISABLE

get-member -InputObject $adsiuser.userAccountControl
gm -i $adsiuser.userAccountControl[0]

$disabled = $adsiuser.UserAccountControl[0] -bor $ADS_UF_ACCOUNTDISABLE
$disabled = $adsiuser.UserAccountControl[0] -bor 2

$disabled
$adsiuser.Put('UserAccountControl',$disabled)
$adsiuser.SetInfo()


Get-ADUser ivanov


#ldapenable

[int32]$ADS_UF_ACCOUNTDISABLE = 2

$adsiuser = [adsi]"LDAP://CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int"
$adsiuser
$adsiuser.userAccountControl

$ADS_UF_ACCOUNTDISABLE

-bnot $ADS_UF_ACCOUNTDISABLE

$enabled = $adsiuser.UserAccountControl[0] -band (-bnot $ADS_UF_ACCOUNTDISABLE)
$enabled

$adsiuser.Put('UserAccountControl',$enabled)
$adsiuser.SetInfo()

Get-ADUser ivanov

#grouptype

Get-ADGroup -Filter {groupCategory -eq 'Security' -and groupScope -eq 'DomainLocal' -and name -like "UserGr*"}

Get-ADGroup -LDAPFilter '(&(groupCategory=Security)(GroupScope=DomainLocal)(Name=UserGr*))'

#grouptype
#https://msdn.microsoft.com/en-us/library/ms675935(v=vs.85).aspx
<#
1 (0x00000001)	Specifies a group that is created by the system.
2 (0x00000002)	Specifies a group with global scope.
4 (0x00000004)	Specifies a group with domain local scope.
8 (0x00000008)	Specifies a group with universal scope.
16 (0x00000010)	Specifies an APP_BASIC group for Windows Server Authorization Manager.
32 (0x00000020)	Specifies an APP_QUERY group for Windows Server Authorization Manager.
2147483648 (0x80000000)	Specifies a security group. If this flag is not set, then the group is a distribution group.
#>

Get-ADGroup -Filter {grouptype -band 0x80000004 -and Name -like "UserGr*"}

#ADObject

Get-ADObject -Filter
Get-ADObject -LDAPFilter
Get-ADObject -Identity

<#
Distinguished Name
GUID (objectGUID)
#>

Get-ADObject -Identity 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int'
Get-ADObject -Identity 'CN=Ivanov Ivan,OU=allusers,DC=domain,DC=int' -Properties *

Get-ADObject -Identity 'CN=comp1,OU=comps,DC=domain,DC=int'
Get-ADObject -Identity 'CN=comp1,OU=comps,DC=domain,DC=int' -Properties *

Get-ADObject -Identity 'CN=UserGroup,OU=groups,DC=domain,DC=int'
Get-ADObject -Identity 'CN=UserGroup,OU=groups,DC=domain,DC=int' -Properties *


#newuser - new and copy

New-ADUser
New-ADUser one

Get-ADUser one | Set-ADAccountPassword -NewPassword $pass
Get-ADUser one | Enable-ADAccount

New-ADUser -Name two -Enabled $true -AccountPassword $pass

New-ADUser -Name three -DisplayName three -GivenName GivenName -Surname Surname -SamAccountName three -UserPrincipalName three@domain.int -Enabled $true -AccountPassword $pass


$ivanov = Get-ADUser ivanov -Properties Title,City,Department
$ivanov.GivenName = 'Pavel'
$ivanov.Surname = 'Pavlov'
$ivanov.UserPrincipalName = 'pavlov@domain.int'
$ivanov
New-ADUser -Instance $ivanov -Name 'Pavlov Pavel' -SamAccountName 'pavlov' -Path $allusersou.DistinguishedName -OtherAttributes @{Comment = 'Nice guy'} -AccountPassword $pass

Get-ADUser pavlov -Properties Department,City,Comment


#redir

Get-ADDomain
Get-ADDomain | fl UsersContainer,ComputersContainer

redirusr.exe /?
redirusr.exe "OU=allusers,DC=domain,dc=int"

redircmp.exe /?
redircmp.exe "OU=comps,DC=domain,DC=int"

Get-ADDomain | fl UsersContainer,ComputersContainer

New-ADUser -Name four
Get-ADUser -Identity four

New-ADComputer -Name comp4
Get-ADComputer -Identity comp4


#lastcreated

Get-ADUser -Filter * -Properties whenCreated

Get-ADUser -Filter * -Properties whenCreated | Sort-Object -Property whenCreated -Descending

Get-ADUser -Filter * -Properties whenCreated | Sort-Object -Property whenCreated -Descending | select -First 5|  fl Name,DistinguishedName,whenCreated


#$PSDefaultParameterValues

Set-ADUser -Identity ivanov -Description "User Ivanov I.I."
Set-ADComputer -Identity comp1 -Description "Computer of Ivanov I.I."


Get-ADUser ivanov

Get-ADComputer comp1

Get-ADUser ivanov -Properties Description

Get-ADComputer comp1 -Properties Description


$PSDefaultParameterValues

$PSDefaultParameterValues = @{'Get-ADUser:Properties' = 'Description'}

$PSDefaultParameterValues

$PSDefaultParameterValues.Add('Get-ADComputer:Properties','Description')

$PSDefaultParameterValues

Get-ADUser ivanov
Get-ADComputer comp1

Get-ADUser ivanov -Properties *
Get-ADUser ivanov -Properties Title,City


#move

Get-ADUser alexandrov

Get-ADUser alexandrov | Move-ADObject -TargetPath $allusersou.DistinguishedName

Get-ADUser alexandrov

#enable, disable

Get-ADUser ivanov | Disable-ADAccount
Get-ADComputer comp1 | Disable-ADAccount

Get-ADUser ivanov
Get-ADComputer comp1

Enable-ADAccount -Identity ivanov
Enable-ADAccount -Identity comp1
Enable-ADAccount -Identity comp1$


#password

$newpass = ConvertTo-SecureString -String 'newPa$$w0rd' -AsPlainText -Force

Set-ADAccountPassword -Identity ivanov -OldPassword $pass -NewPassword $newpass

Set-ADAccountPassword -Identity ivanov -Reset -NewPassword $newpass


#adaccountcontrol

Set-ADAccountControl -

Set-ADAccountControl -Identity ivanov -CannotChangePassword $true -PasswordNeverExpires $true -Enabled $false

Get-ADUser ivanov -Properties UserAccountControl

Set-ADAccountControl -Identity comp4$ -Enabled $false

Get-ADComputer comp4

#Set-ADAccountControl -Identity ivanov -CannotChangePassword $false -PasswordNeverExpires $false

#Get-ADUser ivanov -Properties UserAccountControl


#searchadaccount

Get-ADUser -Filter {Enabled -eq $false}

Search-ADAccount -AccountDisabled 

Search-ADAccount -AccountDisabled | select name


Set-ADAccountExpiration -Identity four -DateTime '11/30/2017'

Search-ADAccount -AccountExpiring -DateTime '12/31/2017'

Search-ADAccount -AccountExpiring -TimeSpan '90.00:00:00'


Search-ADAccount -AccountInactive -DateTime '01/01/2017'
Search-ADAccount -AccountInactive -TimeSpan '90.00:00:00'


Search-ADAccount -LockedOut
Search-ADAccount -LockedOut | Unlock-ADAccount


Search-ADAccount -PasswordNeverExpires


Search-ADAccount -AccountDisabled -UsersOnly
Search-ADAccount -AccountDisabled -ComputersOnly


Set-ADAccountControl -Identity ivanov -CannotChangePassword $false -PasswordNeverExpires $false -Enabled $true
Set-ADAccountControl -Identity comp4$ -Enabled $true


#partition


Get-ADDomain
Get-ADForest
Get-ADRootDSE

Get-ADRootDSE | select *context*


Get-ADObject -Filter {objectClass -eq 'dhcpClass'}

Get-ADObject -Filter {objectClass -eq 'dhcpClass'} -SearchBase "CN=Configuration,DC=Domain,DC=int"


Get-ADObject -Identity "CN=DhcpRoot,CN=NetServices,CN=Services,CN=Configuration,DC=domain,DC=int"

Get-ADObject -Identity "2e7c1560-1a54-4d26-83d5-a7f2f514a54c"


Get-ADObject -Filter {objectClass -eq 'classSchema' -and name  -eq 'User'}

Get-ADObject -Filter {objectClass -eq 'classSchema' -and name  -eq 'User'} -SearchBase "CN=Schema,CN=Configuration,DC=domain,DC=int"

Get-ADObject -Filter {objectClass -eq 'classSchema' -and name  -eq 'User'} -SearchBase "CN=Schema,CN=Configuration,DC=domain,DC=int" -Properties *


Get-ADObject -Identity "CN=User,CN=Schema,CN=Configuration,DC=domain,DC=int"

Get-ADObject -Identity "91a8897f-6e9f-4bc7-87e4-20c75d9b8e94"


#fsmo

Get-ADDomain
Get-ADForest

Move-ADDirectoryServerOperationMasterRole -Identity server -OperationMasterRole DomainNamingMaster, SchemaMaster, InfrastructureMaster, PDCEmulator, RIDMaster

Move-ADDirectoryServerOperationMasterRole -Identity server -OperationMasterRole DomainNamingMaster, SchemaMaster, InfrastructureMaster, PDCEmulator, RIDMaster -Force


#snapshots

netsh.exe interface ipv4 show addresses


ntdsutil.exe snapshot "Activate Instance NTDS" create quit quit

ntdsutil.exe snapshot "list all" quit quit

ntdsutil.exe snapshot "mount {039b30bc-fa4e-4880-bfa5-fb95068c2e04}" quit quit

dsamain
dsamain -dbpath "C:\$SNAP_201709271105_VOLUMEC$\Windows\NTDS\ntds.dit" -ldapport 5000

Remove-ADUser alexandrov -Confirm:$false
Get-ADUser alexandrov

Get-ADUser alexandrov -Server server:5000

ntdsutil.exe snapshot "unmount *" quit quit

ntdsutil.exe snapshot "delete *" quit quit


#ADRecycleBin

Get-ADOptionalFeature -Identity "Recycle Bin Feature"

Enable-ADOptionalFeature -Identity "Recycle Bin Feature" -Scope ForestOrConfigurationSet -Target 'domain.int' -Confirm:$false

Get-ADOptionalFeature -Identity "Recycle Bin Feature"



Get-ADUser pavlov

Remove-ADUser pavlov -Confirm:$false

Get-ADUser pavlov

Get-ADObject -Filter * -SearchBase "CN=Deleted Objects,DC=domain,dc=int"

Get-ADObject -Filter * -SearchBase "CN=Deleted Objects,DC=domain,dc=int" -IncludeDeletedObjects


Get-ADObject -Filter {samAccountName -eq "pavlov"} -SearchBase "CN=Deleted Objects,DC=domain,dc=int" -IncludeDeletedObjects -Properties *

Get-ADObject -Filter {samAccountName -eq "pavlov"} -SearchBase "CN=Deleted Objects,DC=domain,dc=int" -IncludeDeletedObjects -Properties msDS-LastKnownRDN, lastKnownParent

Restore-ADObject -

Get-ADObject -Filter {samAccountName -eq "pavlov"} -SearchBase "CN=Deleted Objects,DC=domain,dc=int" -IncludeDeletedObjects | Restore-ADObject

Get-ADUser pavlov

#drive

Get-PSDrive

cd ad:
ls

cd '.\DC=domain,DC=int'
ls

cd .\OU=allusers
ls

cd\

New-PSDrive -Name allusers -PSProvider ActiveDirectory -Root 'AD:\OU=allusers,DC=domain,DC=int'

Get-PSDrive

ls allusers:\


#dsac
dsac



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

