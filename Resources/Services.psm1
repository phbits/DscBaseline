Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')

Function Get-DscBaselineServices
{
    <#
      .SYNOPSIS
        Generates a Service configuration for DSC based on the local system.    
      .EXAMPLE
        Get-DscBaselineServices
      .EXAMPLE
        Get-DscBaselineServices -FilePath D:\SomeFolder\
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
        ,
        [parameter(Mandatory=$false)]
        [ValidateRange(20,300)]
        [Int]
        # Description text width
        $Width = 100
    )

    [string[]] $dscConfig = @()
    
    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineServices.ps1'

    $dscConfig += 'Configuration DscBaselineServices'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/PowerShell/PSDscResources#service'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module PSDscResources -Name Service'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    $services = Get-WmiObject Win32_Service | Sort-Object Name

    foreach($service in $services)
    {
        $serviceDscName     = Convertto-DscConfigurationName -InputObj $($service.Name)
        $serviceDescription = $service.Description
        $serviceState       = 'Ignore'
        $serviceStart       = $service.StartMode

        if($serviceStart -eq 'Auto')
        {
            $serviceStart = 'Automatic'
        }

        # ServiceState should only be Stopped when StartMode=Disabled
        # since not all services continuously run.
        if($serviceStart -eq 'Disabled')
        {
            $serviceState = 'Stopped'
        }

        # Format service description width
        if($serviceDescription.Length -gt $Width)
        {
            $descriptionIndent  = '                          '
            $serviceDescription = ''
            $wordArray          = $service.Description.Split(' ')
            $spaceLeft          = $Width
 
            foreach($word in $wordArray)
            {
	            if($($word.Length + 1) -gt $spaceLeft)
                {
		            $serviceDescription += "`n$($descriptionIndent)$($word) "
		            $spaceLeft           = $Width - $($word.Length + 1)

	            } else {

		            $serviceDescription += "$word "
		            $spaceLeft          -= $($word.Length + 1)
	            }
            }
        }

        $dscConfig += "$($global:CONFIG_INDENT)Service $($serviceDscName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    <#"
        $dscConfig += "$($global:CONFIG_INDENT)    DisplayName = $($service.DisplayName)"
        $dscConfig += "$($global:CONFIG_INDENT)    Description = $($serviceDescription)"
        $dscConfig += "$($global:CONFIG_INDENT)    Path        = $($service.PathName)"
        $dscConfig += "$($global:CONFIG_INDENT)    ServiceType = $($service.ServiceType)"
        $dscConfig += "$($global:CONFIG_INDENT)    Account     = $($service.StartName)"
        $dscConfig += "$($global:CONFIG_INDENT)    #>"
        $dscConfig += "$($global:CONFIG_INDENT)    Name        = '$($service.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    StartupType = '$($serviceStart)'"
        $dscConfig += "$($global:CONFIG_INDENT)    State       = '$($serviceState)'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineServices -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineServices') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # End Function Get-DscBaselineServices

Export-ModuleMember -Function 'Get-DscBaselineServices'
