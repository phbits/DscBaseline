# Registry key paths for proxy settings
$script:connectionsRegistryKeyPath = 'SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'

Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')

function Get-StringLengthInHexBytes
{
    [CmdletBinding()]
    [OutputType([System.Object[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [AllowEmptyString()]
        [System.String]
        $Value
    )

    $hex = '{0:x8}' -f $Value.Length
    $stringLength = @()
    $stringLength += @('0x' + $hex.Substring(6,2))
    $stringLength += @('0x' + $hex.Substring(4,2))
    $stringLength += @('0x' + $hex.Substring(2,2))
    $stringLength += @('0x' + $hex.Substring(0,2))

    return $stringLength

} # end function Get-StringLengthInHexBytes

function Get-Int32FromByteArray
{
    <#
    .SYNOPSIS
    Gets an int32 from 4 little endian bytes containing in a
    byte array.
    .PARAMETER Bytes
    The bytes containing the little endian int32.
    #>

    [CmdletBinding()]
    [OutputType([System.Int32])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Byte[]]
        $Byte,

        [Parameter(Mandatory = $true)]
        [System.Int32]
        $StartByte
    )

    $value = [System.Int32] 0
    $value += [System.Int32] $Byte[$StartByte]
    $value += [System.Int32] $Byte[$StartByte + 1] -shl 8
    $value += [System.Int32] $Byte[$StartByte + 2] -shl 16
    $value += [System.Int32] $Byte[$StartByte + 3] -shl 24

    return $value

} # end function Get-Int32FromByteArray

function ConvertFrom-ProxySettingsBinary
{
    [CmdletBinding()]
    [OutputType([PSObject])]
    param
    (
        [Parameter(Mandatory = $true)]
        [System.Byte[]]
        $ProxySettings
    )

    $proxyParameters = @{}

    if ($ProxySettings.Count -gt 0)
    {
        # Figure out the proxy settings that are enabled
        $proxyBits = $ProxySettings[8]

        $enableManualProxy = $false
        $enableAutoConfiguration = $false
        $enableAutoDetection = $false

        if (($proxyBits -band 0x2) -gt 0)
        {
            $enableManualProxy = $true
        }

        if (($proxyBits -band 0x4) -gt 0)
        {
            $enableAutoConfiguration = $true
        }

        if (($proxyBits -band 0x8) -gt 0)
        {
            $enableAutoDetection = $true
        }

        $proxyParameters.Add('EnableManualProxy',$enableManualProxy)
        $proxyParameters.Add('EnableAutoConfiguration',$enableAutoConfiguration)
        $proxyParameters.Add('EnableAutoDetection',$enableAutoDetection)

        $stringPointer = 12

        # Extract the Proxy Server string
        $proxyServer = ''
        $stringLength = Get-Int32FromByteArray -Byte $ProxySettings -StartByte $stringPointer
        $stringPointer += 4

        if ($stringLength -gt 0)
        {
            $stringBytes = New-Object -TypeName Byte[] -ArgumentList $stringLength
            $null = [System.Buffer]::BlockCopy($ProxySettings,$stringPointer,$stringBytes,0,$stringLength)
            $proxyServer = [System.Text.Encoding]::ASCII.GetString($stringBytes)
            $stringPointer += $stringLength
        }

        $proxyParameters.Add('ProxyServer',$proxyServer)

        # Extract the Proxy Server Exceptions string
        $proxyServerExceptions = @()
        $stringLength = Get-Int32FromByteArray -Byte $ProxySettings -StartByte $stringPointer
        $stringPointer += 4

        if ($stringLength -gt 0)
        {
            $stringBytes = New-Object -TypeName Byte[] -ArgumentList $stringLength
            $null = [System.Buffer]::BlockCopy($ProxySettings,$stringPointer,$stringBytes,0,$stringLength)
            $proxyServerExceptionsString = [System.Text.Encoding]::ASCII.GetString($stringBytes)
            $stringPointer += $stringLength
            $proxyServerExceptions = [System.String[]] ($proxyServerExceptionsString -split ';')
        }

        if ($proxyServerExceptions.Contains('<local>'))
        {
            $proxyServerExceptions = $proxyServerExceptions | Where-Object -FilterScript { $_ -ne '<local>' }
            $proxyParameters.Add('ProxyServerBypassLocal',$true)
        }
        else
        {
            $proxyParameters.Add('ProxyServerBypassLocal',$false)
        }

        $proxyParameters.Add('ProxyServerExceptions',$proxyServerExceptions)

        # Extract the Auto Config URL string
        $autoConfigURL = ''
        $stringLength = Get-Int32FromByteArray -Byte $ProxySettings -StartByte $stringPointer
        $stringPointer += 4

        if ($stringLength -gt 0)
        {
            $stringBytes = New-Object -TypeName Byte[] -ArgumentList $stringLength
            $null = [System.Buffer]::BlockCopy($ProxySettings,$stringPointer,$stringBytes,0,$stringLength)
            $autoConfigURL = [System.Text.Encoding]::ASCII.GetString($stringBytes)
            $stringPointer += $stringLength
        }

        $proxyParameters.Add('AutoConfigURL',$autoConfigURL)
    }

    return [PSObject] $proxyParameters

} # end function ConvertFrom-ProxySettingsBinary

function Get-TargetResource
{
    [OutputType([System.Collections.Hashtable])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateSet('Yes')]
        [System.String]
        $IsSingleInstance
    )

    $returnValue = @{}

    # Get the registry values in the Connections registry key
    $connectionsRegistryValues = Get-ItemProperty -Path "HKLM:\$($script:connectionsRegistryKeyPath)" `
                                                  -ErrorAction SilentlyContinue

    $proxySettingsRegistryBinary = $null

    if ($connectionsRegistryValues.DefaultConnectionSettings)
    {
        $proxySettingsRegistryBinary = $connectionsRegistryValues.DefaultConnectionSettings
    }
    elseif ($connectionsRegistryValues.SavedLegacySettings)
    {
        $proxySettingsRegistryBinary = $connectionsRegistryValues.SavedLegacySettings
    }

    if ($proxySettingsRegistryBinary)
    {
        $returnValue.Add('Ensure','Present')

        $proxySettings = ConvertFrom-ProxySettingsBinary -ProxySettings $proxySettingsRegistryBinary

        $returnValue.Add('EnableManualProxy',$proxySettings.EnableManualProxy)
        $returnValue.Add('EnableAutoConfiguration',$proxySettings.EnableAutoConfiguration)
        $returnValue.Add('EnableAutoDetection',$proxySettings.EnableAutoDetection)
        $returnValue.Add('ProxyServer',$proxySettings.ProxyServer)
        $returnValue.Add('ProxyServerBypassLocal',$proxySettings.ProxyServerBypassLocal)
        $returnValue.Add('ProxyServerExceptions',$proxySettings.ProxyServerExceptions)
        $returnValue.Add('AutoConfigURL',$proxySettings.AutoConfigURL)
    }
    else
    {
        $returnValue.Add('Ensure','Absent')
    }

    return $returnValue

} # end function Get-TargetResource

function Get-DscBaselineProxySettings
{
    <#
      .SYNOPSIS
        Generates a Proxy Settings DSC configuration based on the local system.
      .DESCRIPTION
        Extracted relevant functions from NetworkDsc source.
      .EXAMPLE
        Get-DscBaselineProxySettings
      .EXAMPLE
        Get-DscBaselineProxySettings -FilePath D:\SomeFolder\
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/blob/master/source/DSCResources/DSC_ProxySettings/DSC_ProxySettings.psm1
    #>

    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save new .ps1 file
        $Folder = (Get-Location).Path
    )
    
    [String[]] $dscConfig = @()
    
    $proxySettings = Get-TargetResource -IsSingleInstance 'Yes'
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineProxySettings.ps1'

    $dscConfig += 'Configuration DscBaselineProxySettings'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/NetworkingDsc/wiki/ProxySettings'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module NetworkingDsc'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    if($proxySettings.Count -gt 0)
    {
        if($proxySettings.Count -gt 1)
        {
            $proxyServerExceptions = Convertto-QuotesAndCommas -InputObj $proxySettings.ProxyServer

            $dscConfig += "$($global:CONFIG_INDENT)ProxySettings ProxySettings"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    IsSingleInstance        = 'Yes'"
            $dscConfig += "$($global:CONFIG_INDENT)    Ensure                  = '$($proxySettings.Ensure)'"
            $dscConfig += "$($global:CONFIG_INDENT)    EnableAutoDetection     = '$($proxySettings.EnableAutoDetection)'"
            $dscConfig += "$($global:CONFIG_INDENT)    EnableAutoConfiguration = '$($proxySettings.EnableAutoConfiguration)'"
            $dscConfig += "$($global:CONFIG_INDENT)    EnableManualProxy       = '$($proxySettings.EnableManualProxy)'"
            $dscConfig += "$($global:CONFIG_INDENT)    ProxyServer             = '$($proxySettings.ProxyServer)'"
            $dscConfig += "$($global:CONFIG_INDENT)    ProxyServerExceptions   = $($proxyServerExceptions)"
            $dscConfig += "$($global:CONFIG_INDENT)    ProxyServerBypassLocal  = '$($proxySettings.ProxyServerBypassLocal)'"
            $dscConfig += "$($global:CONFIG_INDENT)}"

        } else {

            $dscConfig += "$($global:CONFIG_INDENT)ProxySettings ProxySettings"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    IsSingleInstance = 'Yes'"
            $dscConfig += "$($global:CONFIG_INDENT)    Ensure           = '$($proxySettings.Ensure)'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineProxySettings -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineProxySettings') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Get-DscBaselineProxySettings

Export-ModuleMember -Function 'Get-DscBaselineProxySettings'
