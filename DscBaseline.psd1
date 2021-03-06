@{

RootModule = 'DscBaseline.psm1'

ModuleVersion = '1.0'

GUID = '74d9d75a-3841-492b-893f-fbab4e5b8f07'

Author = 'phbits'

CompanyName = 'phbits'

Copyright = '(c) 2020 phbits. All rights reserved.'

Description = @'
Creates DSC configurations based on the localhost where it is launched.
'@

PowerShellVersion = '5.1'

NestedModules = @(
                    'Resources\DscBaseline.helper.psm1',
                    'Resources\AuditPolicy.psm1',
                    'Resources\SecurityPolicy.psm1',
                    'Resources\GroupPolicy.psm1',
                    'Resources\Services.psm1',
                    'Resources\ProxySettings.psm1',
                    'Resources\Network.psm1'
                )

FunctionsToExport = 'Invoke-DscBaseline'

# CmdletsToExport = ''

VariablesToExport = '*'

AliasesToExport = @()

FileList = 'DscBaseline.psd1',
           'DscBaseline.psm1',
           'Resources\AccountPolicyData.psd1',
           'Resources\AuditPolicy.psm1',
           'Resources\DscBaseline.helper.psm1',
           'Resources\GroupPolicy.psm1',
           'Resources\Network.psm1',
           'Resources\ProxySettings.psm1',
           'Resources\SecurityOptionData.psd1',
           'Resources\SecurityPolicy.Helper.psm1',
           'Resources\SecurityPolicy.psm1',
           'Resources\Services.psm1',
           'Resources\UserRightsFriendlyNameConversions.psd1'

PrivateData = @{

    PSData = @{

        Tags = 'Microsoft','DSC','System','Configuration'

        ProjectUri = 'https://github.com/phbits/DscBaseline'

        LicenseUri = 'https://github.com/phbits/DscBaseline/blob/master/LICENSE'

    } # End of PSData hashtable

} # End of PrivateData hashtable

}
