function Invoke-DscBaseline
{
    <#
      .SYNOPSIS
        Creates DSC configurations based on the configuration of the current system.
      .DESCRIPTION
        This PowerShell module was created to expedite the adoption of Microsoft Desired
        State Configuration (DSC) for configuration management. Building these configuration
        files by hand takes far too long and lacks the benfits of a programmatic solution.
        DscBaseline covers common DSC modules and creates configuration files based on the
        system where it is launched.

        Areas covered include: Security Policy, Audit Policy, Service Configurations, Network.

        Some Group Policy settings can be converted to a Registry Setting policy though this
        specific functionality should be considered experimental.
      .EXAMPLE
        Invoke-DscBaseline -Folder D:\WorkingFolder\
      .EXAMPLE
        Invoke-DscBaseline -Folder D:\WorkingFolder\ -TryGroupPolicy -Verbose
      .LINK
        https://github.com/phbits/DscBaseline
    #>

    [OutputType([System.Collections.Hashtable])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$false)]
        [ValidateScript({Test-Path -Path $_ -PathType Container})]
        [String]
        # Folder to save files.
        $Folder = (Get-Location).Path
        ,
        [Parameter(Mandatory=$false)]
        [Switch]
        # EXPERIMENTAL: Build registry configs from Group Policy settings.
        $TryGroupPolicy
    )

    $i = 0
    do
    {
        switch($i)
        {
            0 {
                Write-Verbose -Message 'Verify elevated command prompt is being used.'

                $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
                $isCmdElevated    = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)

                if($isCmdElevated -eq $false)
                {
                    $userMessage = "`n  Invoke-DscBaseline is not running in an elevated command prompt.`n" + `
                                   "  Some configurations will fail to be created by this module.`n" + `
                                   "  Reference: https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/starting-windows-powershell#with-administrative-privileges-run-as-administrator`n" + `
                                   "  Continue? [Y/N]"

                    $userInput   = Read-Host -Prompt $userMessage

                    if($null -eq $userInput)
                    {
                        $i = 100

                    } else {

                        if($userInput.ToString().ToLower().Trim().StartsWith('y') -eq $false)
                        {
                            $i = 100
                        }
                    }
                }
            }
            1 {
                Write-Verbose -Message 'Verify AuditPol.exe can run.'

                $auditPolTest = Test-AuditPol

                if($auditPolTest -eq $false)
                {
                    $userMessage = "`n  Test of auditpol.exe failed. This likely means the current user ($($env:USERDOMAIN)\$($env:USERNAME))`n" + `
                                   "  must be granted the `'Manage Auditing and Security Log`' User Rights Assignment.`n" + `
                                   "  Reference: https://docs.microsoft.com/en-us/windows/security/threat-protection/security-policy-settings/manage-auditing-and-security-log`n" + `
                                   "  Continue? [Y/N]"

                    $userInput   = Read-Host -Prompt $userMessage

                    if($null -eq $userInput)
                    {
                        $i = 100

                    } else {

                        if($userInput.ToString().ToLower().Trim().StartsWith('y') -eq $false)
                        {
                            $i = 100
                        }
                    }
                }
            }
            2 {
                if($TryGroupPolicy)
                {
                    Write-Verbose -Message 'Checking if system is domain joined'

                    if((Get-CimInstance -ClassName Win32_ComputerSystem).PartOfDomain)
                    {
                        $userMessage = "`n  DscBaseline works best on stand alone systems (i.e. non-domain-joined).`n" + `
                                    "  Running this on a domain joined system may produce imcomplete Group Policy results.`n" + `
                                    "  Continue? [Y/N]"

                        $userInput   = Read-Host -Prompt $userMessage

                        if($null -eq $userInput)
                        {
                            $i = 100

                        } else {

                            if($userInput.ToString().ToLower().Trim().StartsWith('y') -eq $false)
                            {
                                $i = 100
                            }
                        }
                    }
                }
            }
            3 {
                Write-Verbose -Message 'Generating Audit Policy DSC Configuration'

                $auditPolicyDscConfig = Get-DscBaselineAuditPolicy -Folder $Folder

                Write-Verbose -Message "  $($auditPolicyDscConfig)"
            }
            4 {
                Write-Verbose -Message 'Generating Security Policy DSC Configuration'

                [hashtable] $securityPolicyDscConfig = Get-DscBaselineSecurityPolicy -Folder $Folder

                $securityPolicyDscConfig.Keys | ForEach-Object{ Write-Verbose -Message "  $($securityPolicyDscConfig[$_])" }
            }
            5 {
                if($TryGroupPolicy)
                {
                    Write-Verbose -Message 'Generating Group Policy DSC Configuration'

                    $groupPolicyDscConfig = Get-DscBaselineGroupPolicy -Folder $Folder

                    Write-Verbose -Message "  $($groupPolicyDscConfig)"
                }
            }
            6 {
                Write-Verbose -Message 'Generating Services DSC Configuration'

                $servicesDscConfig = Get-DscBaselineServices -Folder $Folder

                Write-Verbose -Message "  $($servicesDscConfig)"
            }
            7 {
                Write-Verbose -Message 'Generating Network DSC Configuration'

                $networkDscConfig = Get-DscBaselineNetwork -Folder $Folder

                Write-Verbose -Message "  $($networkDscConfig)"
            }
            8 {
                Write-Verbose -Message 'Generating Proxy Settings DSC Configuration'

                $proxySettingsDscConfig = Get-DscBaselineProxySettings -Folder $Folder

                Write-Verbose -Message "  $($proxySettingsDscConfig)"
            }
            9 {
                Write-Verbose -Message 'Finished creating configuration files.'
                Write-Verbose -Message 'To show newly created configuration files run:'
                Write-Verbose -Message "  Get-ChildItem -Path $($Folder) -File -Filter `"DscBaseline*.ps1`""
            }
            10{
                Write-Verbose -Message 'Generating ApplyDscConfig.ps1'

                $applyDscConfigFile = Join-Path $Folder -ChildPath 'ApplyDscConfig.ps1'

                [string[]] $applyDscConfigFileContents = @()

                $applyDscConfigFileContents += "# These commands can be used to apply DSC configuration files to a system.`n"

                $applyDscConfigFileContents += "# Prevent accidental launch."
                $applyDscConfigFileContents += "return [string] 'ACCIDENT_LAUNCH_PREVENTION_ApplyDscConfig.ps1'"

                $applyDscConfigFileContents += "`n# Install DSC modules. Only needed once."
                $applyDscConfigFileContents += "Install-Module AuditPolicyDsc"
                $applyDscConfigFileContents += "Install-Module NetworkingDsc"
                $applyDscConfigFileContents += "Install-Module PSDscResources"
                $applyDscConfigFileContents += "Install-Module SecurityPolicyDsc"

                $applyDscConfigFileContents += "`n# Reset the Local Configuration Manager (LCM)"
                $applyDscConfigFileContents += 'Reset-LcmConfiguration'

                $applyDscConfigFileContents += "`n# Convert configuration files to .mof (human readable to machine readable)"

                $dscConfigFiles = Get-ChildItem -Path $($Folder) -File -Filter "DscBaseline*.ps1"

                foreach($dscConfigFile in $dscConfigFiles)
                {
                    $applyDscConfigFileContents += "& $($dscConfigFile.FullName) -Verbose"
                }

                $applyDscConfigFileContents += "`n# Prevent the system from rebooting after a configuration is applied."
                $applyDscConfigFileContents += 'Set-LcmSetting -RebootNodeIfNeeded $false -ConfigurationMode ApplyAndAutoCorrect -ActionAfterReboot ContinueConfiguration'

                $applyDscConfigFileContents += "`n# Add each .mof as a partial configuration."

                foreach($dscConfigFile in $dscConfigFiles)
                {
                    $applyDscConfigFileContents += "Add-LcmPartialConfiguration -PartialName `'$($dscConfigFile.BaseName)`' -Description `'$($dscConfigFile.BaseName) Partial Configuration.`' -RefreshMode `'Push`' -Verbose"
                }

                $applyDscConfigFileContents += "`n# Publish the configurations."

                foreach($dscConfigFile in $dscConfigFiles)
                {
                    $applyDscConfigFileContents += "Publish-DscConfiguration -Path $($dscConfigFile.FullName.SubString(0,$dscConfigFile.FullName.Length - 4)) -Verbose"
                }

                $applyDscConfigFileContents += "`n# Start DSC configuration process then get the resulting status."

                $applyDscConfigFileContents += 'Start-DscConfiguration -UseExisting -Verbose -Wait'
                $applyDscConfigFileContents += 'Get-DscConfigurationStatus | Format-List'

                $applyDscConfigFileContents += "`n# To see a detailed list of failed items."
                $applyDscConfigFileContents += 'Get-DscConfigurationStatus | Select-Object -ExpandProperty ResourcesNotInDesiredState'

                Out-File -FilePath $applyDscConfigFile -InputObject $applyDscConfigFileContents -Encoding ASCII -Force

                Write-Verbose -Message "  $applyDscConfigFile"
            }
            default { $i = 100 }
        }

        $i++

    }while($i -lt 100)

    [string[]] $configurationFiles = Get-ChildItem -Path $($Folder) -File -Filter "DscBaseline*.ps1"   | ForEach-Object{ $_.FullName }
    [string]   $applySettingsFile += Get-ChildItem -Path $($Folder) -File -Filter 'ApplyDscConfig.ps1' | ForEach-Object{ $_.FullName }

    return @{
                'ConfigurationFiles' = $configurationFiles;
                'ApplySettingScript' = $applySettingsFile;
            }

} # end function Invoke-DscBaseline
