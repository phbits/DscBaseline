Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')

function Get-GroupPolicyRegistry
{
    <#
      .SYNOPSIS
        Parses gpresults for registry values.
    #>

    [OutputType([System.String[]])]
    [CmdletBinding()]
    param( )

    $returnValue = @()

    [string[]] $contents = Invoke-GPResult

    for($i=0;$i -lt $contents.Length;$i++)
    {
        if([System.String]::IsNullOrWhiteSpace($contents[$i]) -eq $false)
        {
            if($contents[$i].Trim().StartsWith('GPO: '))
            {
                if($contents[$($i+1)].Trim().StartsWith('Folder Id: ') -and `
                $contents[$($i+2)].Trim().StartsWith('Value: ') -and `
                $contents[$($i+3)].Trim().StartsWith('State: '))
                {
                    $regEntry = @{
                                    'GPO'       = "$($contents[$i].Split(':')[1].Trim())";
                                    'Folder Id' = "$($contents[$($i+1)].Split(':')[1].Trim())";
                                    'Value'     = "$($contents[$($i+2)].Split(':')[1].Trim())";
                                    'State'     = "$($contents[$($i+3)].Split(':')[1].Trim())";
                                    'HexValue'  = '';
                                    'ParentFolder' = '';
                                    'ValueType' = '';
                                    'ValueName' = '';
                                }

                    $returnValue += Get-RegistryValueDetails -RegObj $regEntry
                                                                            
                    $i = $i + 3
                }
            }
        }
    }

    return $returnValue

} # end Get-GroupPolicyRegistry

function Invoke-GPResult
{
    <#
      .SYNOPSIS
        Private function that wraps gpresult.exe
      .EXAMPLE
        Invoke-GPResult
      .NOTES
        Modified auditpol.exe wrapper
      .LINK
        https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/AuditPolicyResourceHelper/AuditPolicyResourceHelper.psm1
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    $gpResultReturn = ''

    [string[]] $gpResultArguments = @('/scope COMPUTER','/Z')

    try 
    {
        # Use System.Diagnostics.Process to process the gpresult command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $gpResultArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'gpresult.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $null = $process.Start()
        
        $gpResultReturn = $process.StandardOutput.ReadToEnd()

        if([System.String]::IsNullOrEmpty($gpResultReturn))
        {
            throw

        } else {

            if($gpResultReturn.Trim().ToLower().StartsWith('error: access denied.'))
            {
                throw
            }
        }

        $process.Dispose()
    }
    catch [System.ComponentModel.Win32Exception] {
        # Catch error if the gpresult command is not found on the system
        Write-Error -Message 'gpresult.exe not found.'
    }
    catch {
        
        # Catch the error thrown if the lastexitcode is not 0
        [string] $errorString  = $error[0].Exception + `
                                " `nLASTEXITCODE = $LASTEXITCODE" + `
                                " `nCommand = gpresult.exe $gpResultArguments" + `
                                " `nUser = $($env:USERDOMAIN)\$($env:USERNAME)" + `
                                " `nMake sure that you are running as the local administrator or have opened the command prompt using the `'Run as administrator`' option.`n"
        
        Write-Error -Message $errorString
    }
    
    return $gpResultReturn.Split([System.Environment]::Newline,[System.StringSplitOptions]::RemoveEmptyEntries)

} # end function Invoke-GPResult

function Get-RegistryValueDetails
{
    <#
      .SYNOPSIS
        Gets details of registry value.
      .DESCRIPTION
        Tests multiple hives until a value is found since gpresult output doesn't 
        specify the root hive. While almost always it will be HKLM, adding
        additional checks to be sure.

        Querying the registry key in this manner is necessary to obtain the 
        value type (e.g. SZ, DWORD, etc.)
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.Collections.Hashtable]
        # Registry Object Hashtable
        $RegObj
    )

    $valueTypes = @{ 'REG_SZ'        = 'String';
                     'REG-BINARY'    = 'Binary';
                     'REG_DWORD'     = 'DWord';
                     'REG_QWORD'     = 'QWord';
                     'REG_MULTI_SZ'  = 'MultiString';
                     'REG_EXPAND_SZ' = 'ExpandString';
                    }
    
    [string[]] $registryHives = 'HKEY_LOCAL_MACHINE','HKEY_CURRENT_USER','HKEY_USERS','HKEY_CURRENT_CONFIG','HKEY_CLASSES_ROOT'

    $regKey    = $RegObj['Folder Id'].Split('\')[-1]
    $regParent = $RegObj['Folder Id'].Replace($('\' + $regKey),'')

    for($i=0;$i -lt $registryHives.Length;$i++)
    {
        $queryName = "`"$($registryHives[$i])\$($regParent)`""

        [string[]] $regQuery = Invoke-RegExe -RegistryLocation $queryName

        $result = $regQuery -imatch "^$regKey\s*(REG_SZ|REG-BINARY|REG_DWORD|REG_QWORD|REG_MULTI_SZ|REG_EXPAND_SZ).*$"
   
        if($result -ne $false)
        {
            [string[]] $itemArray = $regQuery[1].Split(' ',[System.StringSplitOptions]::RemoveEmptyEntries) | %{ $_.Trim() }

            $RegObj['HexValue']     = $itemArray[-1]
            $RegObj['ParentFolder'] = Join-Path -Path $registryHives[$i] -ChildPath $regParent
            $RegObj['ValueType']    = $valueTypes[$($itemArray[1])]
            $RegObj['ValueName']    = $regKey
            
            $i = 20
        }
    }

    return $RegObj

} # end function Get-RegistryValueDetails

function Invoke-RegExe
{
    <#
      .SYNOPSIS
        Private function that wraps reg.exe
      .EXAMPLE
        Invoke-RegExe
      .NOTES
        Modified auditpol.exe wrapper
      .LINK
        https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/AuditPolicyResourceHelper/AuditPolicyResourceHelper.psm1
    #>

    [OutputType([System.String[]])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        # Registry location to query
        $RegistryLocation
    )

    # set the base commands to execute
    $regExeArguments = @('query',$RegistryLocation)
    $regExeReturn = ''
    
    try {
        # Use System.Diagnostics.Process to process the reg.exe command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $regExeArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'reg.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        
        if($process.Start())
        {
            [string] $regExeReturn = $process.StandardOutput.ReadToEnd()

            if($regExeReturn -imatch "^.*error: access is denied\..*")
            {
                throw
            
            } else {

                if($regExeReturn -imatch "^\s*$")
                {
                    throw
                }
                
                return $regExeReturn.Split([System.Environment]::Newline,[System.StringSplitOptions]::RemoveEmptyEntries) | %{ $_.Trim() }
            }

        } else { 
        
            throw 
        }
        
        $process.Dispose()
    }
    catch [System.ComponentModel.Win32Exception] {
        # Catch error if the reg.exe command is not found on the system
        Write-Error -Message 'reg.exe not found.'
    }
    catch {
        # Catch the error thrown if the lastexitcode is not 0
        [String] $errorString = $error[0].Exception + `
                               "`nLASTEXITCODE = $LASTEXITCODE" + `
                               " `nCommand = reg.exe $($regExeArguments -Join ' ')" + `
                               " `nUser = $($env:USERDOMAIN)\$($env:USERNAME)" + `
                               " `nUser must be running in an elevated prompt." + `
                               " `nMake sure that you are running as the local administrator or have opened the command prompt using the `'Run as administrator`' option.`n"
        
        Write-Error -Message $errorString
    }

    return $regExeReturn

} # end function Invoke-RegExe

function Get-DscBaselineGroupPolicy
{
    <#
      .SYNOPSIS
        Converts Group Policy registry settings to DSC registry values.
    #>
    
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [System.String]
        # Folder to save new .ps1 file
        $Folder = (Get-Location).Path
    )

    [string[]] $dscConfig = @()
    
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineGroupPolicy.ps1'
    $settings = Get-GroupPolicyRegistry

    $dscConfig += 'Configuration DscBaselineGroupPolicy'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/PowerShell/PSDscResources#registry'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module PSDscResources -Name Registry'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    foreach($entry in $settings)
    {
        if([System.String]::IsNullOrEmpty($entry['ParentFolder']) -eq $false)
        {
            # adding random to ensure name is unique
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($entry['GPO']) $($entry['ValueName']) $(Get-Random -Maximum 9999)"

            $dscConfig += "$($global:CONFIG_INDENT)Registry $dscConfigName"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    Key       = '$($entry['ParentFolder'])'"
            $dscConfig += "$($global:CONFIG_INDENT)    Ensure    = 'Present'"
            $dscConfig += "$($global:CONFIG_INDENT)    ValueName = '$($entry['ValueName'])'"
            $dscConfig += "$($global:CONFIG_INDENT)    ValueType = '$($entry['ValueType'])'"
            $dscConfig += "$($global:CONFIG_INDENT)    ValueData = '$($entry['HexValue'])'"
            $dscConfig += "$($global:CONFIG_INDENT)    Force     = `$true"
            $dscConfig += "$($global:CONFIG_INDENT)    Hex       = `$true"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineGroupPolicy -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineGroupPolicy') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Get-DscBaselineGroupPolicy

Export-ModuleMember -Function 'Get-DscBaselineGroupPolicy'
