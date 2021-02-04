function Invoke-SecEdit
{
    <#
      .SYNOPSIS
        Private function that wraps secedit.exe
      .DESCRIPTION
        If system is domain joined, adds '/mergedpolicy' to secedit arguements to get LSDOU results.
      .EXAMPLE
        Invoke-SecEdit
      .NOTES
        Modified auditpol.exe wrapper
      .LINK
        https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/AuditPolicyResourceHelper/AuditPolicyResourceHelper.psm1
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param()

    $secEditResultFile = ''
    $currentSecurityPolicyFilePath = Join-Path -Path $env:temp -ChildPath "SecurityPolicy_$((Get-Date).ToString('yyyyMMddHmmss')).inf"

    # set the base commands to execute
    [string[]] $seceditArguments = @('/export',"/cfg $currentSecurityPolicyFilePath")

    if((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain)
    {
        # include domain policy with /mergedpolicy
        $seceditArguments += '/mergedpolicy'
    }

    try {
        # Use System.Diagnostics.Process to process the secedit command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $seceditArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'secedit.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $null = $process.Start()

        $processReturn = $process.StandardOutput.ReadToEnd()

        if($processReturn.Trim().StartsWith('You do not have sufficient permissions to perform this command.'))
        {
            throw
        }

        $secEditResultFile = $currentSecurityPolicyFilePath

        Write-Verbose -Message "  File written: $($currentSecurityPolicyFilePath)"

        $process.Dispose()
    }
    catch [System.ComponentModel.Win32Exception] {
        # Catch error if the secedit command is not found on the system
        Write-Error -Message 'secedit.exe not found.'
    }
    catch {
        # Catch the error thrown if the lastexitcode is not 0
        [string] $errorString = $error[0].Exception + `
                               " `nLASTEXITCODE = $LASTEXITCODE" + `
                               " `nCommand = secedit.exe $seceditArguments" + `
                               " `nUser = $($env:USERDOMAIN)\$($env:USERNAME)" + `
                               " `nMake sure that you are running as the local administrator or have opened the command prompt using the `'Run as administrator`' option.`n"

        Write-Error -Message $errorString
    }

    return $secEditResultFile

} # end function Invoke-SecEdit

function ConvertTo-ReverseHashTable
{
    <#
      .SYNOPSIS
        Reverses HashTable by swapping the keys and values.
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param(
            [parameter(Mandatory=$true)]
            [System.Collections.Hashtable]
            # HashTable to reverse.
            $HashTable
    )

    $reverseHashTable = @{}

    foreach($key in $HashTable.Keys)
    {
        $reverseHashTable.Add($HashTable[$key],$key)
    }

    return $reverseHashTable

} # end function ConvertTo-ReverseHashTable

Function Convert-SecurityPolicyIniToHash
{
    <#
      .SYNOPSIS
        Parses configuration file into a hashtable.
      .INPUTS
        System.String
      .OUTPUTS
        System.Collections.Hashtable
      .LINK
        https://blogs.technet.microsoft.com/heyscriptingguy/2011/08/20/use-powershell-to-work-with-any-ini-file/
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
            [parameter(Mandatory=$true)]
            [ValidateScript({Test-Path $_})]
            [string]
            # Path to configuration file.
            $Path
    )

    $config = @{}

    switch -regex -file $Path
    {
        "^.*\[(.+)\].*$" # Section
        {
            $section = $matches[1]

            if($section.ToString().Trim().StartsWith('#') -eq $false)
            {
                $config.Add($section.Trim(),@{})
            }
        }

        "(.+?)\s*=(.*)" # Key
        {
            $name,$value = $matches[1..2]

            if($name.ToString().Trim().StartsWith('#') -eq $false)
            {
                $config[$section].Add($name.Trim(), $value.Trim())
            }
        }
    }

    # remove file once converted to hashtable
    if(Test-Path $Path)
    {
        Remove-Item $Path

        if($(Test-Path $Path) -eq $false)
        {
            Write-Verbose -Message "  Removed File: $($Path)"
        }
    }

    return $config

} # End Function Convert-SecurityPolicyIniToHash

function Get-SecurityPolicyData
{
    <#
      .SYNOPSIS
        Gets security policy data helper files extracted from SecurityPolicyDsc source.
      .LINK
        https://github.com/dsccommunity/SecurityPolicyDsc/tree/master/source
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet("AccountPolicy", "SecurityOption", "UserRights")]
        [System.String]
        $Section
    )
    
    $returnData = @{}
    $filePath = ''

    switch($Section.ToUpper())
    {
        "ACCOUNTPOLICY"  {  $filePath = Join-Path $($PSScriptRoot) -ChildPath 'AccountPolicyData.psd1'  }

        "SECURITYOPTION" {  $filePath = Join-Path $($PSScriptRoot) -ChildPath 'SecurityOptionData.psd1' }

        "USERRIGHTS"     {  $filePath = Join-Path $($PSScriptRoot) -ChildPath 'UserRightsFriendlyNameConversions.psd1'  }
    }

    if([System.String]::IsNullOrEmpty($filePath) -eq $false)
    {
        $returnData = Get-PolicyOptionData -FilePath ($($filePath)).Normalize()
    }

    return $returnData

} # end function Get-SecurityPolicyData

function ConvertTo-LocalFriendlyName
{
    <#
      .SYNOPSIS
        Resolves username or SID to a NTAccount friendly name so desired and actual idnetities can be compared

      .PARAMETER Identity
        An Identity in the form of a friendly name (testUser1,contoso\testUser1) or SID

      .EXAMPLE
        PS C:\> ConvertTo-LocalFriendlyName testuser1
        Server1\TestUser1

        This example demonstrats converting a username without a domain name specified

      .EXAMPLE
        PS C:\> ConvertTo-LocalFriendlyName -Identity S-1-5-21-3084257389-385233670-139165443-1001
        Server1\TestUser1

        This example demonstrats converting a SID to a frendlyname
      .LINK
        https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/source/Modules/SecurityPolicyResourceHelper/SecurityPolicyResourceHelper.psm1
    #>
    [OutPutType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.String[]]
        $Identity
    )

    $friendlyNames = @()
    foreach ($id in $Identity)
    {
        $id = ( $id -replace "\*" ).Trim()
        if ($null -ne $id -and $id -match '^(S-[0-9-]{3,})')
        {
            # if id is a SID convert to a NTAccount
            $friendlyNames += ConvertTo-NTAccount -SID $id -Verbose:$VerbosePreference
        }
        else
        {
            # if id is an friendly name convert it to a sid and then to an NTAccount
            $sidResult = ConvertTo-Sid -Identity $id -Verbose:$VerbosePreference

            if ($sidResult -isnot [System.Security.Principal.SecurityIdentifier])
            {
                continue
            }

            $friendlyNames += ConvertTo-NTAccount -SID $sidResult.Value
        }
    }

    return $friendlyNames

} # end function ConvertTo-LocalFriendlyName

function Test-IdentityIsNull
{
    <#
      .SYNOPSIS
        Tests if the provided Identity is null
      .PARAMETER Identity
        The identity string to test
      .LINK
        https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/source/Modules/SecurityPolicyResourceHelper/SecurityPolicyResourceHelper.psm1
    #>
    [OutputType([bool])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyCollection()]
        [AllowEmptyString()]
        [AllowNull()]
        [System.String[]]
        $Identity
    )

    if ($null -eq $Identity -or [System.String]::IsNullOrWhiteSpace($Identity))
    {
        return $true
    }
    else
    {
        return $false
    }

} # end function Test-IdentityIsNull

function ConvertTo-NTAccount
{
    <#
      .SYNOPSIS
        Convert a SID to a common friendly name
      .PARAMETER SID
        SID of an identity being converted
      .LINK
        https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/source/Modules/SecurityPolicyResourceHelper/SecurityPolicyResourceHelper.psm1
    #>
    [OutPutType([string])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [System.Security.Principal.SecurityIdentifier[]]
        $SID
    )

    $result = @()
    foreach ($id in $SID)
    {
        $id = ( $id -replace "\*" ).Trim()

        $sidId = [System.Security.Principal.SecurityIdentifier]$id
        try
        {
            $result += $sidId.Translate([System.Security.Principal.NTAccount]).value
        }
        catch
        {
            Write-Error -Message "$($error[0])"
        }
    }

    return $result

} # end function ConvertTo-NTAccount

function Get-PolicyOptionData
{
    <#
      .SYNOPSIS
        Retrieves the Security Option Data to map the policy name and values as they appear in the Security Template
        Snap-in.

      .PARAMETER FilePath
        Path to the file containing the Security Option Data
      .LINK
        https://github.com/dsccommunity/SecurityPolicyDsc/blob/master/source/Modules/SecurityPolicyResourceHelper/SecurityPolicyResourceHelper.psm1
    #>
    [OutputType([hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [Microsoft.PowerShell.DesiredStateConfiguration.ArgumentToConfigurationDataTransformation()]
        [System.Collections.Hashtable]
        $FilePath
    )

    return $FilePath

} # end function Get-PolicyOptionData

function ConvertTo-Sid
{
    <#
    .SYNOPSIS
        Converts an identity to a SID to verify it's a valid account

    .PARAMETER Identity
        Specifies the identity to convert

    .NOTES
        SecurityPolicyDsc/source/Modules/SecurityPolicyResourceHelper/SecurityPolicyResourceHelper.psm1
    #>
    [OutputType([System.Security.Principal.SecurityIdentifier])]
    [CmdletBinding()]
    param
    (
        [Parameter()]
        [System.String]
        $Identity,

        [Parameter()]
        [System.String]
        $Scope = 'Get'
    )

    $id = [System.Security.Principal.NTAccount]$Identity
    try
    {
        $result = $id.Translate([System.Security.Principal.SecurityIdentifier])
    }
    catch
    {
        if ($Scope -eq 'Get')
        {
            Write-Verbose -Message ($script:localizedData.ErrorIdToSid -f $Identity)
            $result = $id
        }
        else
        {
            throw "$($script:localizedData.ErrorIdToSid -f $Identity)"
        }
    }

    return $result
    
} # end function ConvertTo-Sid

Export-ModuleMember -Function "*"
