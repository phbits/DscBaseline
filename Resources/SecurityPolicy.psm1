# import helper script modules
Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')
Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'SecurityPolicy.helper.psm1')

function Invoke-AccountPolicy
{
    <#
      .SYNOPSIS
        Creates Account Policy DSC configuration
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateScript({$_.Count -gt 1})]
        [System.Collections.Hashtable]
        # Security Policy configuration hashtable.
        $SecPolObj
        ,
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save Account Policy DSC config.
        $Folder = (Get-Location).Path
    )

    [string[]] $dscConfig = @()

    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineAccountPolicy.ps1'

    $dscConfig += 'Configuration DscBaselineAccountPolicy'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/SecurityPolicyDsc#accountpolicy'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module SecurityPolicyDsc -Name AccountPolicy'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'
    $dscConfig += '        AccountPolicy SecurityPolicy_AccountPolicy'
    $dscConfig += '        {'
    
    [string] $space = (4..45 | ForEach-Object{ ' ' }) -join ''

    $dscConfig += @("$($global:CONFIG_INDENT)    Name$($space)= `'SecurityPolicy_AccountPolicy`'")

    $accountPolicyData = Get-SecurityPolicyData -Section AccountPolicy

    [string[]] $keyList = $accountPolicyData.Keys | Sort-Object

    foreach($key in $keyList)
    {
        $section = $accountPolicyData[$key].Section

        if($SecPolObj.ContainsKey($section))
        {
            if($SecPolObj[$section].ContainsKey($accountPolicyData[$key].Value))
            {
                $value = ''

                if($key -eq 'Maximum_Password_Age')
                {
                    # Maximum_Password_Age could be -1 which needs to be 0 for DSC config.
                    [int] $maxPassAgeValue = $SecPolObj[$section][$($accountPolicyData[$key].Value)]

                    if($maxPassAgeValue -lt 0)
                    {
                        $value = '0'
                    
                    } else {

                        $value = $maxPassAgeValue
                    }
                
                } else {
                
                    if($accountPolicyData[$key].Option.ContainsKey('String'))
                    {
                        $value = $SecPolObj[$section][$($accountPolicyData[$key].Value)]

                    } else {

                        $reverseHash = ConvertTo-ReverseHashTable $accountPolicyData[$key].Option

                        $value = $reverseHash[$($SecPolObj[$section][$($accountPolicyData[$key].Value)])]
                    }
                }
                
                # format output
                [string] $space = ' '

                if($key.Length -lt 44)
                {
                    $key.Length..44 | ForEach-Object{ $space = $space + ' ' }
                }
    
                if($key.ToLower() -eq 'password_must_meet_complexity_requirements' -or $key.ToLower() -eq 'store_passwords_using_reversible_encryption')
                {
                    $dscConfig += "$($global:CONFIG_INDENT)    $($key)$($space)= '$($value)'"

                } else {
                    
                    $dscConfig += "$($global:CONFIG_INDENT)    $($key)$($space)= $($value)"
                }
            }
        }
    }

    $dscConfig += '        }'
    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineAccountPolicy -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineAccountPolicy') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Invoke-AccountPolicy

function Invoke-SecurityOption
{
    <#
      .SYNOPSIS
        Creates Security Option DSC configuration
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateScript({$_.Count -gt 1})]
        [System.Collections.Hashtable]
        # Security Policy configuration object.
        $SecPolObj
        ,
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save Security Option DSC config.
        $Folder = (Get-Location).Path
    )

    [string[]] $dscConfig = @()
    
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineSecurityOption.ps1'

    $dscConfig += 'Configuration DscBaselineSecurityOption'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/SecurityPolicyDsc#securityoption'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module SecurityPolicyDsc -Name SecurityOption'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'
    $dscConfig += '        SecurityOption SecurityPolicy_SecurityOption'
    $dscConfig += '        {'
    
    [string] $space = (4..100 | ForEach-Object{ ' ' }) -join ''

    $dscConfig += @("$($global:CONFIG_INDENT)    Name$($space)= `'SecurityPolicy_SecurityOption`'")

    $securityOptionData = Get-SecurityPolicyData -Section SecurityOption

    [string[]] $keyList = $securityOptionData.Keys | Sort-Object

    foreach($key in $keyList)
    {
        $section = $securityOptionData[$key].Section

        if($SecPolObj.ContainsKey($section))
        {
            if($SecPolObj[$section].ContainsKey($securityOptionData[$key].Value))
            {
                $value = ''
            
                if($securityOptionData[$key].Option.ContainsKey('String'))
                {
                    $value = $SecPolObj[$section][$($securityOptionData[$key].Value)]

                    # get any string prefix 
                    $stringValue = $securityOptionData[$key].Option.string

                    # remove any string prefix
                    $value = $value.Substring($stringValue.Length, $($value.Length - $stringValue.Length))

                } else {

                    $reverseHash = ConvertTo-ReverseHashTable $securityOptionData[$key].Option

                    $value = $reverseHash[$($SecPolObj[$section][$($securityOptionData[$key].Value)])]
                }

                if($null -ne $value)
                {
                    if($value.StartsWith('"') -eq $true -and $value.EndsWith('"') -eq $true)
                    {
                        $value = $value.Substring(1,$($value.Length -2))
                    } 
                    
                    $value = "`'$($value)`'"
                
                } else {

                    if($key.ToUpper() -eq 'NETWORK_SECURITY_CONFIGURE_ENCRYPTION_TYPES_ALLOWED_FOR_KERBEROS')
                    {
                        $value = Convertto-QuotesAndCommas -InputObj @('RC4_HMAC_MD5','AES128_HMAC_SHA1','AES256_HMAC_SHA1','FUTURE')
                    }
                }

                # format output
                [string] $space = ' '
                
                if($key.Length -lt 100)
                {
                    $key.Length..99 | ForEach-Object{ $space = $space + ' ' }
                }
    
                if($value -eq "''")
                {
                    # Settings with empty values can produce errors. Keeping config
                    # though commenting it out for future configurations.
                    $dscConfig += "$($global:CONFIG_INDENT)   #$($key)$($space)= $($value)"

                } else {

                    $dscConfig += "$($global:CONFIG_INDENT)    $($key)$($space)= $($value)"
                }
            }
        }
    }

    $dscConfig += '        }'
    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineSecurityOption -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineSecurityOption') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Invoke-SecurityOption

function Invoke-UserRights
{
    <#
      .SYNOPSIS
        Creates User Rights DSC configuration
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [ValidateScript({$_.Count -gt 1})]
        [System.Collections.Hashtable]
        # Security Policy configuration object.
        $SecPolObj
        ,
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save User Rights DSC config.
        $Folder = (Get-Location).Path
    )

    [string[]] $dscConfig = @()
    
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineUserRightsAssignment.ps1'

    $dscConfig += 'Configuration DscBaselineUserRightsAssignment'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/SecurityPolicyDsc#userrightsassignment'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module SecurityPolicyDsc -Name UserRightsAssignment'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    $userRightsData = Get-SecurityPolicyData -Section UserRights

    [string[]] $keyList = $userRightsData.Keys | Sort-Object

    foreach($key in $keyList)
    {
        if($SecPolObj.ContainsKey('Privilege Rights'))
        {
            if($SecPolObj['Privilege Rights'].ContainsKey($userRightsData[$key]))
            {
                [string[]] $splitChars = ',','*'

                $sids = $SecPolObj['Privilege Rights'][$($userRightsData[$key])]

                [string[]] $sidsArray = $sids.Split($splitChars,[System.StringSplitOptions]::RemoveEmptyEntries)

                [string[]] $friendlyNames = ConvertTo-LocalFriendlyName -Identity $sidsArray

                $identityValue = Convertto-QuotesAndCommas -InputObj $friendlyNames
                $dscName       = Convertto-DscConfigurationName "$($key) UserRightsAssignment"

                $dscConfig += "$($global:CONFIG_INDENT)UserRightsAssignment $($dscName)"
                $dscConfig += "$($global:CONFIG_INDENT){"
                $dscConfig += "$($global:CONFIG_INDENT)    Policy      = `'$($key)`'"
                $dscConfig += "$($global:CONFIG_INDENT)    Identity    = $($identityValue)"
                $dscConfig += "$($global:CONFIG_INDENT)    Ensure      = `'Present`'"
                $dscConfig += "$($global:CONFIG_INDENT)}"
            }
        }
    }

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineUserRightsAssignment -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineUserRightsAssignment') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Invoke-UserRights

function Get-DscBaselineSecurityPolicy
{
    <#
      .SYNOPSIS
        Generates a Security Policy DSC configuration based on the local system.
      .EXAMPLE
        Get-DscBaselineSecurityPolicy
      .EXAMPLE
        Get-DscBaselineSecurityPolicy -FilePath D:\SomeFolder\
    #>
    
    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save new .ps1 file
        $Folder = (Get-Location).Path
    )

    $dscConfigFiles = @{}

    $securityPolicyResultFile = Invoke-SecEdit

    if($null -ne $securityPolicyResultFile)
    {
        $securityPolicyObject = Convert-SecurityPolicyIniToHash -Path $securityPolicyResultFile

        for($i=1;$i -lt 4; $i++)
        {
            switch($i)
            {
                1 { # ACCOUNTPOLICY
                
                    $accountPolicyDscConfig = Invoke-AccountPolicy -SecPolObj $securityPolicyObject -Folder $Folder

                    $dscConfigFiles.Add('AccountPolicy', $accountPolicyDscConfig)
                }
                2 { # SECURITYOPTION

                    $securityOptionDscConfig = Invoke-SecurityOption -SecPolObj $securityPolicyObject -Folder $Folder

                    $dscConfigFiles.Add('SecurityOption', $securityOptionDscConfig)
                }
                3 { # USERRIGHTS

                    $userRightsDscConfig = Invoke-UserRights -SecPolObj $securityPolicyObject -Folder $Folder

                    $dscConfigFiles.Add('UserRights', $userRightsDscConfig)
                }
            }
        }
    }

    return $dscConfigFiles

} # end function Get-DscBaselineSecurityPolicy

Export-ModuleMember -Function 'Get-DscBaselineSecurityPolicy'
