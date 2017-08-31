break
#08

#where

Get-Process | where Name -Like powershell
                    
Get-Process | where Name -Like pow*

Get-Process | where Name -Like pow

ps | ? Name -Like pow*



ps | ? Name -match pow

ps | ? Name -match wer

ps | ? Name -match rshell




#Get-Process | where {$_.Name -like "powershell" -and $_.ws -gt 1000}

#Get-Process | where Name -like "powershell" -and ws -gt 1000


#Get-Process | where {$_.Name -like powershell -and $_.ws -gt 1000}

#ps | ? Name -Match rshell
#ps | ? -Property Name -Match -Value rshell

Get-Process | where {$_.Name -like "powershell" -and $_.ws -gt 1000}



ps | ? {$_.Name -like "powershell" -and $_.ws -gt 1000}

ps | ? {$_.Name -like "pow*" -and $_.ws -gt 1000}


ps | ? {$_.Name -match "pow" -and $_.ws -gt 1000}

ps | ? {$_.Name -match "rshe" -and $_.ws -gt 1000}


#-match
#scalar and array
##array

#'First string', 'Second string', 'Third string' -match 'string'

$string = @"
Circles and rings, dragons and kings
Weaving a charm and a spell
Blessed by the night, holy and bright
Called by the toll of the bell
"@

#(c) Black Sabbath, 1980.

$string.count

#\r\n  -  13, 10

$string -split '\r\n' 

$s = $string -split '\r\n'

$s.Count

$s[0]


$s -match 'll'

(Get-Process).Name -match 'rshe'


Get-ADUser -Filter {UserPrincipalName -like "someuser*"}
Get-ADUser -Filter {UserPrincipalName -match "someuser"}


Get-ADComputer -Filter {OperatingSystem -like "*10 Pro*" -and Enabled -eq $True} -Properties memberof | sort name | select name, memberof | Format-Table -AutoSize

Get-ADComputer -Filter {OperatingSystem -like "*10 Pro*" -and Enabled -eq $True} -Properties memberof | sort name | select name, @{Name="Special_Group"; Expression = {$_.memberof -match "special"}} | Format-Table -AutoSize

Get-ADComputer -Filter {OperatingSystem -like "*10 Pro*" -and Enabled -eq $True} -Properties memberof | select name, @{Name="Special_Group"; Expression = {$_.memberof -match "special"}} | sort Special_Group | Format-Table -AutoSize


##scalar

$s[3]

$s[3] -match 'll'

$s[2]

$s[2] -match 'll'

$s[2] -match 'ght'

$Matches


$s[2] -notmatch 'by the'

$Matches


$s -match 'll'

$Matches



$ip = '192.168.11.1'

$ip -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
$ip -match '(\d{1,3}\.){3}\d{1,3}'

$Matches



#syntax

$string.count
$s.Count

##string
$s -match 'i'

$s -match 'ings'


##symbol group
$s -match '[ings]'

$s -match '[nsig]'

$s -notmatch '[ings]'

##range
$s -match '[a-z]'
$s -match '[A-Z]'

##negation
$s -match '[^a-z]'
$s -match '[^a-z ]'
$s -match '[^a-z\s]'
$s -match '[^a-z\s,]'


#ipconfig
$ipconfig = ipconfig
$ipconfig

$ipconfig.Count


##.
$ipconfig -match 'ipv. a'

'Some sentence . with a point in the middle' -match '.'
$Matches

'Some sentence . with a point in the middle' -match '\.'
$Matches


##w

'Some sentence . with a point in the middle' -match '\w\w\w'
$Matches

'Some sentence . with a point in the middle' -match '\W'
$Matches

'Some sentence . with a point in the middle' -match '..\W..'
$Matches

'1st day of the month.' -match '\w\w\w'
$Matches

'_is a word character too' -match '\w\w\w'
$Matches

##d

'Symbols like 1, 2, 3, 4 and 5 is a decimal digits' -match '\d'
$Matches

'Symbols like 1, 2, 3, 4 and 5 is a decimal digits' -match '\D'
$Matches

'Symbols like 1, 2, 3, 4 and 5 is a decimal digits' -match '[^\d]'
$Matches

' Symbols like 1, 2, 3, 4 and 5 is a decimal digits' -match '\D....'
$Matches


##s

'Whitespace - is a symbol' -match '..\s....'
$Matches

'Whitespace - is a symbol' -match '\S....'
$Matches




#^$
##^
###stringArray

$s

$s -match 'b'

$s -match '^b'
$s -match '\Ab'

###hereString
$string
$string -match '^c'
$string -match '^w'


[regex]::IsMatch($string,'^C')
[regex]::IsMatch($string,'^W')

[regex]::IsMatch($string,'^C','Multiline')
[regex]::IsMatch($string,'^W','Multiline')

[regex]::IsMatch($string,'\AC','Multiline')
[regex]::IsMatch($string,'\AW','Multiline')

# https://docs.microsoft.com/en-us/dotnet/standard/base-types/regular-expression-language-quick-reference#anchors

<#
[regex]::IsMatch
[enum]::GetNames([System.Text.RegularExpressions.RegexOptions])

[regex]::IsMatch($string,'^c','Multiline')
[regex]::IsMatch($string,'^c','Multiline','IgnoreCase')
[regex]::IsMatch($string,'^c',('Multiline','IgnoreCase'))


[regex]::IsMatch($string,'^W','Multiline')
[regex]::IsMatch($string,'\AW','Multiline')
[regex]::IsMatch($string,'\AC','Multiline')

####arraysToStrings
[regex]::IsMatch($s,'^W')
[regex]::IsMatch($s,'^W','Multiline')

[regex]::Match($s,'.*','Multiline')

foreach($ss in $s)
{
    [regex]::Match($ss,'^Weaving.*')
}
#>



##$
###stringArray
$s -match 't'
$s -match 't$'
$s -match 't\z'
$s -match 't\Z'

###hereString

$string
$string -match '..................ll$'
$Matches

$string -match '..................ll$\Z'
$Matches

$string -match '..................ll$\z'
$Matches


[regex]::Match($string,'..................ll$','Multiline')
[regex]::Match($string,'..................ll\Z','Multiline')
[regex]::Match($string,'..................ll\z','Multiline')

$string
[regex]::Match($string,'..................ll$','Multiline')
[regex]::Match($string,'..................ll\r$','Multiline')



#Weaving a charm and a spell\r\n

$s1 = "Weaving a charm and a spell\r\n"
$s1
$s1 = "Weaving a charm and a spell`r`n"
$s1

[regex]::Match($s1,'..................ll\Z')
[regex]::Match($s1,'..................ll\r\Z')
[regex]::Match($s1,'..................ll\r\n\Z')

[regex]::Match($s1,'..................ll\r\z')
[regex]::Match($s1,'..................ll\r\n\z')


#\b - Word Boundary

$ip = '192.168.11.1'

$ip -match '\b\d\d\b'
$Matches

$ip -match '\b\.\b'
$Matches

$ip -match '...\b.\b...'
$Matches

$notip = '.,!a/|\'
$notip -match '...\b.\b...'
$Matches

'abc' -match '\b...\b'
'!!!' -match '\b...\b'


#\B - Non-Word Boundary

'!abcdef' -match '\B\w\w\w\B'
$Matches

'!ab.!/' -match '\B...\B'
$Matches



#quantifiers
##*

$ip

$ip -match '\d*'
$Matches

$ip -match '\d*\.!*\d*'
$Matches

$ip -match '\d*\.!\d*'


##?

$ip -match '\d*\.?!?\d*'
$Matches

##+

$ip -match '\d+\.+\d+'
$Matches

$ip -match '\d+\.+!+\d+'


##{}

$ip
$ip -match '\.\d{2}'
$Matches



$ip -match '\.\d{2,}'
$Matches

$ip -match '\.\d{1,}'
$Matches



$ip -match '\.\d{1,2}'
$Matches

$ip -match '\.\d{2,3}'
$Matches

#[regex]::Matches($ip, '\.\d{2,3}')


#? - Lazy Match
##*?

$ip -match '\.\d*'
$Matches

$ip -match '\.\d*?'
$Matches



$ip -match '\.\d??'
$Matches



$ip -match '\.\d+'
$Matches

$ip -match '\.\d+?'
$Matches





$ip -match '\.\d{2}?'
$Matches



$ip -match '\.\d{2,}'
$Matches
$ip -match '\.\d{2,}?'
$Matches


$ip -match '\.\d{1,2}'
$Matches

$ip -match '\.\d{1,2}?'
$Matches



#regex
[regex] | Get-Member -Static

[regex]::IsMatch($ip, '\.\d{2,3}')

[regex]::Match($ip, '\.\d{2,3}')

[regex]::Match($ip, '\.\d{2,3}!+')

$ip -match '\.\d{2,3}'
$Matches
$Matches | fl *

[regex]::Matches($ip, '\.\d{2,3}')

[regex]::Matches($ip, '\.\d{1,3}')

$res = [regex]::Matches($ip, '\.\d{1,3}')
$res
$res[0]
$res[1]
$res[2]


#G - Contiguous Matches

$line = 'hydrogen, helium, lithium, berillium'

[regex]::Matches($line, '\w+')
[regex]::Matches($line, '\G\w+')
[regex]::Matches($line, '\G\w+, ')
[regex]::Matches($line, '\G\w+(, )?')






#\p
#https://msdn.microsoft.com/en-us/library/20bw873z(v=vs.110).aspx
    #https://docs.microsoft.com/en-us/dotnet/standard/base-types/character-classes-in-regular-expressions
#http://www.unicode.org/reports/tr44/    # 5.7.1 General Category Values

##Categories

###L - Letter

'abc' -match '\p{Lu}'
'abc' -match '\p{Ll}'

'abc' -cmatch '\p{Lu}'
'abc' -cmatch '\p{Ll}'

[regex]::Match('abc','\p{Lu}+')
[regex]::Match('abc','\p{Ll}+')

[regex]::Match('abc','\p{Lu}+','IgnoreCase')
[regex]::Match('abc','\p{Ll}+','IgnoreCase')

# 'abc' -cmatch '\P{Lu}'
# 'abc' -cmatch '\P{Ll}'


'abc' -match '\p{L}+'
$Matches



###N - Number

'123' -match '\p{Nd}+'
$Matches

'123' -match '\p{N}+'
$Matches


###[char]
[char] | Get-Member -Static

[char]::GetUnicodeCategory

[char]::GetUnicodeCategory('a')
[char]::GetUnicodeCategory('L')
[char]::GetUnicodeCategory('1')

[char]::GetUnicodeCategory('-')
[char]::GetUnicodeCategory('_')
[char]::GetUnicodeCategory('.')
[char]::GetUnicodeCategory(',')
[char]::GetUnicodeCategory('!')

[char]::GetUnicodeCategory('(')
[char]::GetUnicodeCategory(')')

[char]::GetUnicodeCategory('[')
[char]::GetUnicodeCategory(']')

[char]::GetUnicodeCategory('<')
[char]::GetUnicodeCategory('>')

[char]::GetUnicodeCategory('`')
[char]::GetUnicodeCategory('\')

[char]::GetUnicodeCategory('"')
[char]::GetUnicodeCategory("'")

$ip -match '(\p{Nd}{1,3}\p{Po}){3}\p{Nd}{1,3}'
$Matches


##Named Blocks
'C' -match '\p{IsCyrillic}'
'—' -match '\p{IsCyrillic}'

'E' -match '\p{IsBasicLatin}'
'≈' -match '\p{IsBasicLatin}'


'¿·‚„‰Â' -match '\p{IsCyrillic}+'
$Matches

'¿·‚„‰Â' -match '^\p{IsCyrillic}+$'
$Matches


'Abcdef' -match '^\p{IsBasicLatin}+$'
$Matches

#//russian_c
'AbÒdef' -match '^\p{IsBasicLatin}+$'




#|
$in1 = 'first, second, third'
$in2 = 'first; second; third'
$in3 = 'first/second/third'

$in = @($in1, $in2, $in3)

$in

$in -match '^(\w+(, |; |/)){2}\w+$'



$ip = '192.168.11.1'

$ip -match '^(\d{1,3}\.){3}\d{1,3}$'
$Matches

$ip -match '^(\d{1,3}(\.|$)){4}$'
$Matches




#groups
##numbered

$ip

$ip -match '\d+\.\d+\.\d+\.\d+'
$Matches

$ip -match '(\d+)\.(\d+)\.(\d+)\.(\d+)'
$Matches
$Matches[0]
$Matches[1]
$Matches[2]
$Matches[3]
$Matches[4]


$ip -match '(((\d+)\.\d+)\.\d+)\.\d+'
$Matches


##named

$ip -match '(?<first_octet>\d+)\.(?<second_octet>\d+)\.(?<third_octet>\d+)\.(?<fourth_octet>\d+)'
$Matches
$Matches.first_octet
$Matches.second_octet
$Matches.third_octet
$Matches.fourth_octet




###ip
function f
{
    Param(
    [ValidatePattern('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')]
    $IpAddress
    )

    "IPAddress is: $IPAddress"
}

f -IpAddress 192.168.11.1
f -IpAddress 192.168.11.1111
f -IpAddress 999.999.999.999



function ff
{
    Param(
    [ValidateScript(
    {
        if($_ -match '^(?<one>\d{1,3})\.(?<two>\d{1,3})\.(?<three>\d{1,3})\.(?<four>\d{1,3})$')
        {
            foreach($i in 'one','two','three','four')
            {
                if([int]$Matches[$i] -lt 0 -or [int]$Matches[$i] -gt 255)
                {
                    return $false
                }
            }
        return $true
        }
        else {return $false}
    })]
    $IpAddress
    )

    "IPAddress is: $IPAddress"
}

ff -IpAddress 192.168.11.1
ff -IpAddress 192.168.11.1111
ff -IpAddress 192.168.11.999




#noncapturing
$ip -match '(\d+\.){3}\d+'
$Matches

$ip -match '(?:\d+\.){3}\d+'
$Matches


#inline option
##n - Explicit Capture

$ip -match '(?n:\d+\.){3}\d+'
$Matches

$ip -match '(?n:\d+\.){3}(\d+)'
$Matches



$ip -match '(?n)(\d+\.){3}\d+'
$Matches

$ip -match '(?n)(\d+\.){3}(\d+)'
$Matches

$ip -match '(\d+\.){3}(?n)(\d+)'
$Matches



##i - Case Insensitive

$s[0] -match 'Rings'
$Matches

$s[0] -match '(?i)Rings'
$s[0] -imatch 'Rings'
$Matches


$s[0] -match '(?-i)Rings'
$Matches

$s[0] -match '(?-i)rings'
$Matches


$s[0] -cmatch 'Rings'
$Matches

$s[0] -cmatch 'rings'
$Matches



##m - Multiline

$string
$string.count

$string -match '..............ll$'
$Matches

$string -match '(?m)...ll\r$'
$Matches

$string -match '(?m)(...ll)\r$'
$Matches


##s - Singleline
$line = "Line`r`n"

$line -match 'l...'
$Matches

$line -match 'l....'
$Matches

$line -match 'l.....'
$Matches

$line -match '(?s)l.....'
$Matches
$Matches[0].length
[int]$Matches[0][-2]
[int]$Matches[0][-1]


##x - Ignore Pattern Whitespace

$ip
$ip -match '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'

$ip -match '\d{1,3} \. \d{1,3} \. \d{1,3} \. \d{1,3}'

$ip -match '(?x) \d{1,3} \. \d{1,3} \. \d{1,3} \. \d{1,3}'
$Matches


'Sentence with several whitespaces' -match 'with several'
$Matches

'Sentence with several whitespaces' -match '(?x)with several'

'Sentence with several whitespaces' -match '(?x)with\ several'
$Matches

'Sentence with several whitespaces' -match '(?x) with \ several'
$Matches



## # - Comment

$ip -match '(?# ipv4 address pattern)\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
$Matches




#balancing_group
'Some words "may be in" quotes' -match '.*(?<start>").*(?<end-start>").*'
$Matches
$Matches.end


'Some words "may" be "in" quotes' -match '(?:[^"]*(?<start>")[^"]*(?<end-start>"))+.*'
$Matches
$Matches.end

[regex]::Match('Some words "may" be "in" quotes', '(?:[^"]*(?<start>")[^"]*(?<end-start>"))+.*')
$out = [regex]::Match('Some words "may" be "in" quotes', '(?:[^"]*(?<start>")[^"]*(?<end-start>"))+.*')

$out
$out.Groups
$out.Groups[0]
$out.Groups['start']
$out.Groups['end']
$out.Groups['end'].Captures




#?= - Zero-width positive lookahead assertion

'abc2abc!!!' -match '\w+(?=\d)'
$Matches

'abc2abc!!!' -match '\w+'
$Matches

'abc2abc!!!' -match '\w+(?=\d)'
$Matches

'abc2abc!!!' -match '\w+(?=\d).*'
$Matches


'abc2abc!!!' -match '(?=\d)\w+'
$Matches




#?! - Zero-width negative lookahead assertion

'2abcabc!!!', 'abcabc2', '!abc' -match '^(?!\d).*'




#?<= - Zero-width positive lookbehind assertion

'abcdef' -match '\w*(?<=d)'
$Matches




#?<! - Zero-width negative lookbehind assertion

'abcdef' -match '\w*(?<!f)'
$Matches

'abcdef' -match '\w*'
$Matches

'abcdef' -match '\w*(?<!f)'
$Matches



#backreference

$in1 = 'first, second, third'
$in2 = 'first; second; third'
$in3 = 'first/second/third'

$in = @($in1, $in2, $in3)

$in -match '^(\w+(, |; |/)){2}\w+$'

##number
$in4 = 'first, second; third'
$in = @($in1, $in2, $in3, $in4)
$in -match '^(\w+(, |; |/)){2}\w+$'

$in -match '^\w+(, |; |/)\w+\1\w+$'

##name
$in -match '^\w+(?<delimiter>, |; |/)\w+\k<delimiter>\w+$'



#"if" (Alteration construst)
$mac1 = '12:34:56:78:90:AB'
$mac2 = '12-34-56-78-90-AB'
$mac3 = '1234.5678.90AB'

##expression
$mac1 -match '(?x) [0-9a-f]{2} (?(:|-)(?<del>:|-)) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} '
$mac2 -match '(?x) [0-9a-f]{2} (?(:|-)(?<del>:|-)) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} '
$mac3 -match '(?x) [0-9a-f]{2} (?(:|-)(?<del>:|-)) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} (?(:|-)\k<del>|\.) [0-9a-f]{2} (?(:|-)\k<del>) [0-9a-f]{2} '
$Matches

##group existence
$mac1 -match '(?x) [0-9a-f]{2} (?<del>:|-)? [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} '
$mac2 -match '(?x) [0-9a-f]{2} (?<del>:|-)? [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} '
$mac3 -match '(?x) [0-9a-f]{2} (?<del>:|-)? [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} (?(del)\k<del>|\.) [0-9a-f]{2} (?(del)\k<del>) [0-9a-f]{2} '
$Matches




#Substitute

##number and name

'one 2 three' -replace '2', 'two'


'one two three' -replace '(\w+) (\w+) (\w+)', '$3 $2 $1'

'one two three zero' -replace '(\w+) (\w+) (\w+)', '$3 $2 $1'

'one two three' -replace '(?<first>\w+) (?<second>\w+) (?<third>\w+)', '${third} ${second} ${first}'




#[regex]:Repalce and Result

[regex]::Replace('one 2 three', '2', 'two')
[regex]::Replace('one two three', '(\w+) (\w+) (\w+)', '$3 $2 $1')

[regex]::Match('one two three', '(\w+) (\w+) (\w+)')
$res = [regex]::Match('one two three', '(\w+) (\w+) (\w+)')

$res

$res | Get-Member
$res.Result

$res
$res.Groups

$res.Result('$3 $2 $1')


#<=back
#quotes

$Variable = 'This is variable.'
$Variable

"$Variable"
'$Variable'

'one two three' -replace '(\w+) (\w+) (\w+)', '$3 $2 $1'
'one two three' -replace '(?<first>\w+) (?<second>\w+) (?<third>\w+)', '${third} ${second} ${first}'

'one two three' -replace '(\w+) (\w+) (\w+)', "$3 $2 $1"
'one two three' -replace '(?<first>\w+) (?<second>\w+) (?<third>\w+)', "${third} ${second} ${first}"

${variable with spaces, and other punctuation marks!} = 'The content of the variable!!!'
${variable with spaces, and other punctuation marks!}


#replace
'one two three' -replace '^(\w+\s)', ''
'one two three' -replace '^(\w+\s)', '1 '



##$ - dollar sign

'1 2 3' -replace '(\d+)', '$1$'

'1 2 3' -replace '(\d+)', '$115'

'1 2 3' -replace '(\d+)', '$1'
'1 2 3' -replace '(\d+)', '$$1'


'1 2 3' -replace '(\d+)', '$1$'
'1 2 3' -replace '(\d+)', '$1$$'
'1 2 3' -replace '(\d+)', '$1$$$'
'1 2 3' -replace '(\d+)', '$1$$$$'



##$& - whole match

'abc2def3ghi' -replace '\d', ' ($&) '



##$` -before the match


'1234'  -replace '\d', '$`'


##$' - after the match

'1234'  -replace '\d', "$'"



##$+ - last captured group

'abc2def' -replace '\w+(\d)\w+', '..$+..'

'abc2def' -replace '(\w+)(\d)\w+', '..$+..'

'abc2def' -replace '(\w+)(\d)(\w+)', '..$+..'


'abc2def' -replace '\d', '..$+..'


##$_ - entire input sting

'abc2def' -replace '\w+(\d)\w+', 'this is the subset ($+) of the entire input ($_)'



#example

cd\

New-Item -ItemType File -Path c:\file1.gif
New-Item -ItemType File -Path c:\file2.gif
ls c:\*.gif

#ls c:\*.gif | foreach {$PSItem.ToString()}


#Get-ChildItem | Rename-Item -NewName { $_ -Replace '.gif$','.jpg$' }

ls c:\*.gif | Rename-Item -NewName { $_.Name -Replace '\.gif$','.jpg' }

#ls *.jpg | Rename-Item -NewName { $_ -Replace '.jpg$','.gif' }

ls *.jpg




#[regex]

#escape
[regex]::Escape

[regex]::Escape('Spaces, periods .; backslashes \ and other (|:) special _/*. symbols!')
$match = [regex]::Escape('Spaces, periods .; backslashes \ and other (|:) special _/*. symbols!')

'Spaces, periods .; backslashes \ and other (|:) special _/*. symbols!' -match $match
$Matches


'S/paces, periods .; backslashes \ and other (|:) special _/*. symbols!' -match $match


$match
[regex]::Unescape($match)




#contructor
[regex]::new

[regex]::new('\w{3}')
$reg = [regex]::new('\w{3}')

$reg | Get-Member
$reg.IsMatch('aaabbb')
$reg.Match('aaabbb')
$reg.Matches('aaabbb')


[regex]::new('\d+')
$reg2 = [regex]::new('\d+')

# whole match

$reg2.Replace('abc123def',' ($&) ')   


#split


-split 'Some line of text.'


'abc/def/ghi' -split '/'

[char]::GetUnicodeCategory('/')

'abc/def/ghi' -split '\p{Po}'


[regex]::Split
[regex]::Split('abc/def/ghi','\p{Po}')


$reg3 = [regex]::new('\p{Po}')
$reg3.Split
$reg3.Split('abc/def/ghi')







#macs
$mac1 = '12:34:56:78:90:AB'
$mac2 = '12-34-56-78-90-AB'
$mac3 = '1234.5678.90AB'
$mac4 = '12:34:56-78-90-AB'

$mac1 -match '([0-9a-f]{2}(?(del)\k<del>|((?<del>:|-)?))[0-9a-f]{2}((?(del)\k<del>|\.)|$)){3}'
$mac2 -match '([0-9a-f]{2}(?(del)\k<del>|((?<del>:|-)?))[0-9a-f]{2}((?(del)\k<del>|\.)|$)){3}'
$mac3 -match '([0-9a-f]{2}(?(del)\k<del>|((?<del>:|-)?))[0-9a-f]{2}((?(del)\k<del>|\.)|$)){3}'
$mac4 -match '([0-9a-f]{2}(?(del)\k<del>|((?<del>:|-)?))[0-9a-f]{2}((?(del)\k<del>|\.)|$)){3}'
$Matches




#¡ÎÓ„
sergeyvasin.net

#Twitter
twitter.com/vsseth

#√ÛÔÔ˚
fb.com/inpowershell
vk.com/inpowershell

#GitHub
github.com/sethvs/PowerShell-UserGroup

