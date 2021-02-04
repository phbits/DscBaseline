Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')

function Get-DscBaselineAuditPolicy
{
    <#
      .SYNOPSIS
        Generates an Audit Policy DSC configuration based on the local system.
      .EXAMPLE
        Get-DscBaselineAuditPolicy
      .EXAMPLE
        Get-DscBaselineAuditPolicy -FilePath D:\SomeFolder\
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

    $auditPolHashtable = Get-AuditPolicy
    
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineAuditPolicy.ps1'

    [string[]] $dscConfig = @()

    $dscConfig += 'Configuration DscBaselineAuditPolicy'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/AuditPolicyDsc'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module AuditPolicyDsc'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    [string[]] $policies = $auditPolHashtable.Keys | Sort-Object

    foreach($policy in $policies)
    {
        $dscName = Convertto-DscConfigurationName -InputObj $policy
        
        $ensureSuccess = 'Absent'
        $ensureFailure = 'Absent'

        if($auditPolHashtable[$policy].ToUpper() -eq 'SUCCESS AND FAILURE')
        {
            $ensureSuccess = 'Present'
            $ensureFailure = 'Present'

        } else {

            if($auditPolHashtable[$policy].ToUpper() -eq 'SUCCESS')
            {
                $ensureSuccess = 'Present'
            }

            if($auditPolHashtable[$policy].ToUpper() -eq 'FAILURE')
            {
                $ensureFailure = 'Present'
            }
        }

        $dscConfig += "$($global:CONFIG_INDENT)AuditPolicySubcategory $($dscName)_Success"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name      = '$policy'"
        $dscConfig += "$($global:CONFIG_INDENT)    AuditFlag = 'Success'"
        $dscConfig += "$($global:CONFIG_INDENT)    Ensure    = '$ensureSuccess'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
        $dscConfig += "$($global:CONFIG_INDENT)AuditPolicySubcategory $($dscName)_Failure"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name      = '$policy'"
        $dscConfig += "$($global:CONFIG_INDENT)    AuditFlag = 'Failure'"
        $dscConfig += "$($global:CONFIG_INDENT)    Ensure    = '$ensureFailure'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineAuditPolicy -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineAuditPolicy') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Get-DscBaselineAuditPolicy

function Get-AuditPolicy
{
    <#
      .SYNOPSIS
        Gets audit policy from localhost.
      .DESCRIPTION
        Parses result of auditpol command and loads it into a hashtable.
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param()

    $returnValue = @{}

    [string[]] $auditPolResults = Invoke-AuditPol

    foreach($auditPolResult in $auditPolResults)
    {
        if($auditPolResult -imatch "^(.*)\s*(No Auditing|Success and Failure|Success|Failure)$")
        {
            if($auditPolResult -imatch "^(.*)No Auditing$")
            {
                $returnValue.Add($($auditPolResult.Replace('No Auditing','').Trim()),'No Auditing')

            } else {

                if($auditPolResult -imatch "^(.*)Success and Failure$")
                {
                    $returnValue.Add($($auditPolResult.Replace('Success and Failure','').Trim()),'Success and Failure')
                
                } else {

                    if($auditPolResult -imatch "^(.*)Success")
                    {
                        $returnValue.Add($($auditPolResult.Replace('Success','').Trim()),'Success')
                    }

                    if($auditPolResult -imatch "^(.*)Failure$")
                    {
                        $returnValue.Add($($auditPolResult.Replace('Failure','').Trim()),'Failure')
                    }
                }
            }
        }
    }

    return $returnValue

} # end function Get-AuditPolicy

function Invoke-AuditPol
{
    <#
      .SYNOPSIS
        Private function that wraps auditpol.exe
      .EXAMPLE
        Invoke-AuditPol
      .LINK
        https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/AuditPolicyResourceHelper/AuditPolicyResourceHelper.psm1
    #>

    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    $auditpolArguments = @('/get','/category:*')
    
    try {
        # Use System.Diagnostics.Process to process the auditpol command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $auditpolArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'auditpol.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $null = $process.Start()

        [string] $auditpolReturn = $process.StandardOutput.ReadToEnd()

        # auditpol does not throw exceptions, so test the results and throw if needed
        if ($process.ExitCode -ne 0) {
            throw
        }

        $process.Dispose()
    }
    catch [System.ComponentModel.Win32Exception] {
        # Catch error if the auditpol command is not found on the system
        Write-Error -Message 'auditpol.exe not found.'
    }
    catch {
        # Catch the error thrown if the lastexitcode is not 0
        [string] $errorString = $error[0].Exception + `
                               "`nLASTEXITCODE = $LASTEXITCODE" + `
                               " `nCommand = auditpol $auditpolArguments" + `
                               " `nUser = $($env:USERDOMAIN)\$($env:USERNAME)" + `
                               " `nUser must be running in an elevated prompt." + `
                               " `nUser must be granted `'Manage auditing and security log`' User Rights Assignment."

        Write-Error -Message $errorString
    }

    return $auditpolReturn.Split([System.Environment]::Newline,[System.StringSplitOptions]::RemoveEmptyEntries) | %{ $_.Trim() }

} # end function Invoke-AuditPol

function Test-AuditPol
{
    <#
      .SYNOPSIS
        Tests if auditpol.exe can run.
      .DESCRIPTION
        Modified auditpol.exe wrapper
      .EXAMPLE
        Test-AuditPol
      .LINK
        https://github.com/dsccommunity/AuditPolicyDsc/blob/dev/DSCResources/AuditPolicyResourceHelper/AuditPolicyResourceHelper.psm1
    #>

    [OutputType([boolean])]
    [CmdletBinding()]
    param()

    $auditpolArguments = @('/get','/category:*')
    $testResult = $false
    
    try {
        # Use System.Diagnostics.Process to process the auditpol command
        $process = New-Object System.Diagnostics.Process
        $process.StartInfo.Arguments = $auditpolArguments
        $process.StartInfo.CreateNoWindow = $true
        $process.StartInfo.FileName = 'auditpol.exe'
        $process.StartInfo.RedirectStandardOutput = $true
        $process.StartInfo.UseShellExecute = $false
        $null = $process.Start()

        $null = $process.StandardOutput.ReadToEnd()

        # auditpol does not throw exceptions, so test the results and throw if needed
        if($process.ExitCode -ne 0)
        {
            return $false
        
        } else {

            return $true
        }

        $process.Dispose()
    }
    catch [System.ComponentModel.Win32Exception] {
        # Catch error if the auditpol command is not found on the system
        Write-Error -Message 'auditpol.exe not found.'
    }
    catch {
        # Catch the error thrown if the lastexitcode is not 0
        [string] $errorString = $error[0].Exception + `
                               "`nLASTEXITCODE = $LASTEXITCODE" + `
                               " `nCommand = auditpol $auditpolArguments" + `
                               " `nUser = $($env:USERDOMAIN)\$($env:USERNAME)" + `
                               " `nUser must be running in an elevated prompt." + `
                               " `nUser must be granted `'Manage auditing and security log`' User Rights Assignment."

        Write-Error -Message $errorString
    }

    return $testResult

} # end function Test-AuditPol

Export-ModuleMember -Function 'Get-DscBaselineAuditPolicy','Test-AuditPol'
