Import-Module $(Join-Path -Path $PSScriptRoot -ChildPath 'DscBaseline.helper.psm1')


$allowedProperties = @( 'AdaptiveIFS','ITR','LogLinkStateEvent','MasterSlave','NetworkAddress', `
    'MaxRxRing1Length','NumRxBuffersSmall','RxIntModeration','RxIntModerationProfile', `
    'TxIntModerationProfile','VlanID','WaitAutoNegComplete','*DcbxMode','*EncapsulatedPacketTaskOffload', `
    '*FlowControl','*InterruptModeration','*IPChecksumOffloadIPv4','*JumboPacket','*LsoV2IPv4', `
    '*LsoV2IPv6','*MaxRssProcessors','*NetworkDirect','*NumaNodeId','*NumRssQueues','*PacketDirect', `
    '*PriorityVLANTag','*QOS','*ReceiveBuffers','*RecvCompletionMethod','*RoceMaxFrameSize','*RscIPv4', `
    '*RSS','*RssBaseProcNumber','*RssMaxProcNumber','*RssOnHostVPorts','*RSSProfile','*SpeedDuplex', `
    '*Sriov','*TCPChecksumOffloadIPv4','*TCPChecksumOffloadIPv6','*TCPUDPChecksumOffloadIPv4', `
    '*TCPUDPChecksumOffloadIPv6','*TransmitBuffers','*UDPChecksumOffloadIPv4','*UDPChecksumOffloadIPv6', `
    '*VMQ','*VMQVlanFiltering' )

[System.Collections.Generic.HashSet[string]] $script:acceptedAdvancedPropertyValues = @{}

$allowedProperties | %{ $script:acceptedAdvancedPropertyValues.Add($_) | Out-Null }

Function Get-DefaultGatewayDscConfig
{
    <#
      .SYNOPSIS
        Generates a Default Gateway DSC configuration based on the local system.
      .DESCRIPTION
        Interface must NOT be DHCP=Enabled
      .EXAMPLE
        Get-DefaultGatewayDscConfig
    #>

    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [string[]] $dscConfig = @()
    
    # loopback adapters rarely (never?) need to be configured, thus excluding
    $adapters = Get-NetIPConfiguration -All | ?{ $_.InterfaceAlias.ToLower().StartsWith('loopback') -eq $false } | Sort-Object InterfaceAlias

    foreach($adapter in $adapters)
    {
        $ipv4StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily 'IPv4' `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        if($null -ne $ipv4StaticAddress)
        {
            $hasDefaultGateway = $false

            if([system.string]::IsNullOrEmpty($adapter.IPv4DefaultGateway) -eq $false)
            {
                if([system.string]::IsNullOrEmpty($adapter.IPv4DefaultGateway.NextHop) -eq $false)
                {
                    $hasDefaultGateway = $true
                    $dscConfigName     = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv4 SetDefaultGateway"

                    $dscConfig += "$($global:CONFIG_INDENT)DefaultGatewayAddress $($dscConfigName)"
                    $dscConfig += "$($global:CONFIG_INDENT){"
                    $dscConfig += "$($global:CONFIG_INDENT)    Address        = '$($adapter.IPv4DefaultGateway.NextHop)'"
                    $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
                    $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv4'"
                    $dscConfig += "$($global:CONFIG_INDENT)}"
                }
            }

            if($hasDefaultGateway -eq $false)
            {
                $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv4 RemoveDefaultGateway"

                $dscConfig += "$($global:CONFIG_INDENT)DefaultGatewayAddress $($dscConfigName)"
                $dscConfig += "$($global:CONFIG_INDENT){"
                $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
                $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv4'"
                $dscConfig += "$($global:CONFIG_INDENT)}"
            }
        }

        $ipv6StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily 'IPv6' `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        if($null -ne $ipv6StaticAddress)
        {
            $hasDefaultGateway = $false

            if([system.string]::IsNullOrEmpty($adapter.IPv6DefaultGateway) -eq $false)
            {
                if([system.string]::IsNullOrEmpty($adapter.IPv6DefaultGateway.NextHop) -eq $false)
                {
                    $hasDefaultGateway = $true
                    $dscConfigName     = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv6 SetDefaultGateway"

                    $dscConfig += "$($global:CONFIG_INDENT)DefaultGatewayAddress $($dscConfigName)"
                    $dscConfig += "$($global:CONFIG_INDENT){"
                    $dscConfig += "$($global:CONFIG_INDENT)    Address        = '$($adapter.IPv6DefaultGateway.NextHop)'"
                    $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
                    $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv6'"
                    $dscConfig += "$($global:CONFIG_INDENT)}"
                }
            }
                
            if($hasDefaultGateway -eq $false)
            {
                $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv6 RemoveDefaultGateway"

                $dscConfig += "$($global:CONFIG_INDENT)DefaultGatewayAddress $($dscConfigName)"
                $dscConfig += "$($global:CONFIG_INDENT){"
                $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
                $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv6'"
                $dscConfig += "$($global:CONFIG_INDENT)}"
            }
        }
    }

    return $dscConfig

} # End Function Get-DefaultGatewayDscConfig

function Get-DnsClientGlobalSettingDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Dns Client Global Setting DSC configuration based on the local system.     
      .EXAMPLE
        Get-DnsClientGlobalSettingDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/DnsClientGlobalSetting
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [string[]] $dscConfig = @()

    $dnsClientGlobalSettings = Get-DnsClientGlobalSetting
    $suffixSearchList        = Convertto-QuotesAndCommas -InputObj $DnsClientGlobalSettings.SuffixSearchList
    $useDevolution           = Get-BooleanAsString -InputObj $DnsClientGlobalSettings.UseDevolution

    $dscConfig += "$($global:CONFIG_INDENT)DnsClientGlobalSetting DnsClientGlobalSetting"
    $dscConfig += "$($global:CONFIG_INDENT){"
    $dscConfig += "$($global:CONFIG_INDENT)    IsSingleInstance = 'Yes'"
    $dscConfig += "$($global:CONFIG_INDENT)    SuffixSearchList = $($suffixSearchList)"
    $dscConfig += "$($global:CONFIG_INDENT)    UseDevolution    = $($useDevolution)"
    $dscConfig += "$($global:CONFIG_INDENT)    DevolutionLevel  = $($dnsClientGlobalSettings.DevolutionLevel)"
    $dscConfig += "$($global:CONFIG_INDENT)}"

    return $dscConfig

} # end function Get-DnsClientGlobalSettingDscConfiguration

function Get-DnsConnectionSuffixDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a DNS Connection Suffix DSC configuration based on the local system.     
      .EXAMPLE
        Get-DnsConnectionSuffixDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/DnsConnectionSuffix
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [string[]] $dscConfig = @()

    # loopback adapters rarely (never?) need to be configured, thus excluding
    $dnsClientSettings = Get-DnsClient | ?{ $_.InterfaceAlias.ToLower().StartsWith('loopback') -eq $false } | Sort-Object InterfaceAlias

    foreach($adapter in $dnsClientSettings)    
    {
        # check if dhcp is enabled
        $ipv4StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily 'IPv4' `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        $ipv6StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily 'IPv6' `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        if($null -ne $ipv4StaticAddress -and $null -ne $ipv6StaticAddress)
        {
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) DnsConnectionSuffix"

            $dscConfig += "$($global:CONFIG_INDENT)DnsConnectionSuffix $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias                  = '$($adapter.InterfaceAlias)'"
            $dscConfig += "$($global:CONFIG_INDENT)    ConnectionSpecificSuffix        = '$($adapter.ConnectionSpecificSuffix)'"
            $dscConfig += "$($global:CONFIG_INDENT)    RegisterThisConnectionsAddress  = '$($adapter.RegisterThisConnectionsAddress)'"
            $dscConfig += "$($global:CONFIG_INDENT)    UseSuffixWhenRegistering        = '$($adapter.UseSuffixWhenRegistering)'"
            $dscConfig += "$($global:CONFIG_INDENT)    Ensure                          = 'Present'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }
    return $dscConfig

} # end function Get-DnsConnectionSuffixDscConfiguration

function Get-DnsServerAddressDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a DNS Server Address DSC configuration based on the local system.     
      .EXAMPLE
        Get-DnsServerAddressDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/DnsServerAddress
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [string[]] $dscConfig = @()

    # loopback adapters rarely (never?) need to be configured, thus excluding
    $dnsServerAddresses  = Get-DnsClientServerAddress | ?{ $_.InterfaceAlias.ToLower().StartsWith('loopback') -eq $false } | Sort-Object InterfaceAlias, AddressFamily

    foreach($adapter in $dnsServerAddresses)    
    {
        # check if dhcp is enabled
        $staticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                            -AddressFamily $($adapter.AddressFamily) `
                                            -Dhcp Disabled `
                                            -ErrorAction SilentlyContinue

        if($null -ne $staticAddress)
        {
            $addressFamily = 'IPv4'

            if($adapter.AddressFamily -eq 23)
            {
                $addressFamily = 'IPv6'
            }

            $dnsServers    = Convertto-QuotesAndCommas -InputObj $adapter.ServerAddresses
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) $($addressFamily) DnsServerAddress"

            $dscConfig += "$($global:CONFIG_INDENT)DnsServerAddress $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    Address        = $dnsServers"
            $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
            $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = '$($addressFamily)'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    return $dscConfig

} # end function Get-DnsServerAddressDscConfiguration

function Get-IPAddressDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a static IP address DSC configuration based on the local system.     
      .EXAMPLE
        Get-IPAddressDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/IPAddress
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()

    # loopback adapters rarely (never?) need to be configured, thus excluding
    [System.Object[]] $adapters  = Get-NetIPConfiguration -All | ?{ $_.InterfaceAlias.ToLower().StartsWith('loopback') -eq $false } | Sort-Object InterfaceAlias

    foreach($adapter in $adapters)
    {
        $ipv4Address = "`'`'"
        $ipv6Address = "`'`'"

        # check if dhcp is enabled
        $ipv4StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily ipv4 `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        if($null -ne $ipv4StaticAddress)
        {
            if($adapter.IPv4Address.Count -gt 0)
            {
                if($adapter.IPv4Address.Count -gt 1)
                {
                    $ipv4AddressArray = @()

                    foreach($ipv4 in $adapter.IPv4Address)
                    {
                        $ipv4AddressArray += "`'$($ipv4.IPAddress)/$($ipv4.PrefixLength)`'"
                    }

                    $ipv4Address = $ipv4AddressArray -Join ','

                } else {

                    $ipv4Address = "`'$($adapter.IPv4Address.IPAddress)/$($adapter.IPv4Address.PrefixLength)`'"
                }
            }

            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv4 IPv4Address"

            $dscConfig += "$($global:CONFIG_INDENT)IPAddress $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    IPAddress      = $($ipv4Address)"
            $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
            $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv4'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }

        # check if dhcp is enabled
        $ipv6StaticAddress = Get-NetIPInterface -InterfaceIndex $($adapter.InterfaceIndex) `
                                                -AddressFamily ipv6 `
                                                -Dhcp Disabled `
                                                -ErrorAction SilentlyContinue

        if($null -ne $ipv6StaticAddress)
        {
            if($adapter.IPv6Address.Count -gt 0)
            {
                if($adapter.IPv6Address.Count -gt 1)
                {
                    $ipv6AddressArray = @()

                    foreach($ipv6 in $adapter.IPv6Address)
                    {
                        $ipv6AddressArray += "`'$($ipv6.IPAddress)/$($ipv6.PrefixLength)`'"
                    }

                    $ipv6Address = $ipv6AddressArray -Join ','

                } else {

                    $ipv6Address = "`'$($adapter.IPv6Address.IPAddress)/$($adapter.IPv6Address.PrefixLength)`'"
                }
            }

            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) IPv6 NewIPv6Address"

            $dscConfig += "$($global:CONFIG_INDENT)IPAddress $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    IPAddress      = $($ipv6Address)"
            $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.InterfaceAlias)'"
            $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily  = 'IPv6'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    return $dscConfig

} # end function Get-IPAddressDscConfiguration

function Get-NetAdapterAdvancedPropertyDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter Advanced Property DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterAdvancedPropertyDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterAdvancedProperty
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $properties = Get-NetAdapterAdvancedProperty | Sort-Object Name, RegistryKeyword

    foreach($property in $properties)
    {
        if($script:acceptedAdvancedPropertyValues.Contains($property))
        {
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($property.Name) $($property.RegistryKeyword)"

            $dscConfig += "$($global:CONFIG_INDENT)NetAdapterAdvancedProperty $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    NetworkAdapterName = '$($property.Name)'"
            $dscConfig += "$($global:CONFIG_INDENT)    RegistryKeyword    = '$($property.RegistryKeyword)'"
            $dscConfig += "$($global:CONFIG_INDENT)    RegistryValue      = '$($property.RegistryValue)'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    return $dscConfig

} # end function Get-NetAdapterAdvancedPropertyDscConfiguration

function Get-NetAdapterBindingDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter Binding DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterBindingDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterBinding
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $bindings = Get-NetAdapterBinding | Sort-Object Name, ComponentID

    foreach($binding in $bindings)
    {
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($binding.Name) $($binding.ComponentID)"
        $bindingState  = 'Disabled'

        if($binding.Enabled -eq $true)
        {
            $bindingState = 'Enabled'
        }

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterBinding $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    <#"
        $dscConfig += "$($global:CONFIG_INDENT)    Display Name   = '$($binding.DisplayName)'"
        $dscConfig += "$($global:CONFIG_INDENT)    #>"
        $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($binding.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    ComponentId    = '$($binding.ComponentID)'"
        $dscConfig += "$($global:CONFIG_INDENT)    State          = '$($BindingState)'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetAdapterBindingDscConfiguration

function Get-NetAdapterLsoDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter LSO DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterLsoDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterLso
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapterLso | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) V1IPv4 NetAdapterLso"

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterLso  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'V1IPv4'"
        $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.V1IPv4Enabled)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
        <#
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) IPv4 NetAdapterLso"

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterLso  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'IPv4'"
        $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.IPv4Enabled)"
        $dscConfig += "$($global:CONFIG_INDENT)}"

        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) IPv6 NetAdapterLso"

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterLso  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'IPv6'"
        $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.IPv6Enabled)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
        #>
    }

    return $dscConfig

} # end function Get-NetAdapterLsoDscConfiguration

function Get-NetAdapterRdmaDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter Rdma DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterRdmaDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterRdma
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapterRdma | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) NetAdapterRdma"

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterRdma  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name    = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Enabled = `$$($adapter.Enabled)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetAdapterRdmaDscConfiguration

function Get-NetAdapterRscDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter Rsc DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterRscDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterRsc
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapterRsc | Sort-Object Name

    foreach($adapter in $adapters)
    {
        if($adapter.IPv4Enabled -and $adapter.IPv6Enabled)
        {
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) All NetAdapterRsc"

            $dscConfig += "$($global:CONFIG_INDENT)NetAdapterRsc  $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
            $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'All'"
            $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.IPv4Enabled)"
            $dscConfig += "$($global:CONFIG_INDENT)}"

        } else {

            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) IPv4 NetAdapterRsc"

            $dscConfig += "$($global:CONFIG_INDENT)NetAdapterRsc  $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
            $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'IPv4'"
            $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.IPv4Enabled)"
            $dscConfig += "$($global:CONFIG_INDENT)}"
            
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) IPv6 NetAdapterRsc"

            $dscConfig += "$($global:CONFIG_INDENT)NetAdapterRsc  $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    Name     = '$($adapter.Name)'"
            $dscConfig += "$($global:CONFIG_INDENT)    Protocol = 'IPv6'"
            $dscConfig += "$($global:CONFIG_INDENT)    State    = `$$($adapter.IPv6Enabled)"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    return $dscConfig

} # end function Get-NetAdapterRscDscConfiguration

function Get-NetAdapterRssDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter Rss DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterRssDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterRss
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapterRss | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) NetAdapterRss"

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterRss  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name    = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Enabled = `$$($adapter.Enabled)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetAdapterRssDscConfiguration

function Get-NetAdapterStateDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Adapter State DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetAdapterStateDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetAdapterState
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapter | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $adapterState  = 'Enabled'
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) NetAdapterState"

        if($adapter.State -eq 3)
        {
            $adapterState = 'Disabled'
        }

        $dscConfig += "$($global:CONFIG_INDENT)NetAdapterState  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name  = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    State = '$($adapterState)'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetAdapterStateDscConfiguration

function Get-NetBiosDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a NetBios DSC configuration based on the local system.
      .EXAMPLE
        Get-NetBiosDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetBios
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()
    
    $adapters = Get-NetAdapter | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $dscConfigName  = Convertto-DscConfigurationName -InputObj "$($adapter.Name) NetBios"
        $netBiosSetting = Get-NetAdapterNetbiosOptionsFromRegistry -NetworkAdapterGUID $adapter.InterfaceGuid

        $dscConfig += "$($global:CONFIG_INDENT)NetBios $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($adapter.Name)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Setting        = '$($netBiosSetting)'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetBiosDscConfiguration

function Get-NetConnectionProfileDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net Connection Profile DSC configuration based on the local system.
      .EXAMPLE
        Get-NetConnectionProfileDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetConnectionProfile
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()

    $adapters = Get-NetAdapter | Sort-Object Name

    foreach($adapter in $adapters)
    {
        $netConnectionProfile = Get-NetConnectionProfile -InterfaceIndex $($adapter.ifIndex) -ErrorAction SilentlyContinue

        if($null -ne $netConnectionProfile)
        {
            $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.Name) NetConnectionProfile"

            $dscConfig += "$($global:CONFIG_INDENT)NetConnectionProfile  $($dscConfigName)"
            $dscConfig += "$($global:CONFIG_INDENT){"
            $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias   = '$($adapter.Name)'"
            $dscConfig += "$($global:CONFIG_INDENT)    IPv4Connectivity = '$($netConnectionProfile.IPv4Connectivity)'"
            $dscConfig += "$($global:CONFIG_INDENT)    IPv6Connectivity = '$($netConnectionProfile.IPv6Connectivity)'"
            $dscConfig += "$($global:CONFIG_INDENT)    NetworkCategory  = '$($netConnectionProfile.NetworkCategory)'"
            $dscConfig += "$($global:CONFIG_INDENT)}"
        }
    }

    return $dscConfig

} # end function Get-NetConnectionProfileDscConfiguration

function Get-NetIPInterfaceDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Net IP Interface DSC configuration based on the local system.     
      .EXAMPLE
        Get-NetIPInterfaceDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/NetIPInterface
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()

    $adapters = Get-NetIPInterface | Where-Object{ $_.InterfaceAlias.ToLower().StartsWith('loopback') -eq $false } | Sort-Object InterfaceAlias, AddressFamily

    foreach($adapter in $adapters)
    {
        $dscConfigName = Convertto-DscConfigurationName -InputObj "$($adapter.InterfaceAlias) $($adapter.AddressFamily) NetIPInterface"

        $dscConfig += "$($global:CONFIG_INDENT)NetIPInterface  $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias                  = '$($adapter.InterfaceAlias)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AddressFamily                   = '$($adapter.AddressFamily)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AdvertiseDefaultRoute           = '$($adapter.AdvertiseDefaultRoute)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Advertising                     = '$($adapter.Advertising)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AutomaticMetric                 = '$($adapter.AutomaticMetric)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Dhcp                            = '$($adapter.Dhcp)'"
        $dscConfig += "$($global:CONFIG_INDENT)    DirectedMacWolPattern           = '$($adapter.DirectedMacWolPattern)'"
        $dscConfig += "$($global:CONFIG_INDENT)    EcnMarking                      = '$($adapter.EcnMarking)'"
        $dscConfig += "$($global:CONFIG_INDENT)    ForceArpNdWolPattern            = '$($adapter.ForceArpNdWolPattern)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Forwarding                      = '$($adapter.Forwarding)'"
        $dscConfig += "$($global:CONFIG_INDENT)    IgnoreDefaultRoutes             = '$($adapter.IgnoreDefaultRoutes)'"
        $dscConfig += "$($global:CONFIG_INDENT)    ManagedAddressConfiguration     = '$($adapter.ManagedAddressConfiguration)'"
        $dscConfig += "$($global:CONFIG_INDENT)    NeighborUnreachabilityDetection = '$($adapter.NeighborUnreachabilityDetection)'"
        $dscConfig += "$($global:CONFIG_INDENT)    OtherStatefulConfiguration      = '$($adapter.OtherStatefulConfiguration)'"
        $dscConfig += "$($global:CONFIG_INDENT)    RouterDiscovery                 = '$($adapter.RouterDiscovery)'"
        $dscConfig += "$($global:CONFIG_INDENT)    WeakHostReceive                 = '$($adapter.WeakHostReceive)'"
        $dscConfig += "$($global:CONFIG_INDENT)    WeakHostSend                    = '$($adapter.WeakHostSend)'"
        $dscConfig += "$($global:CONFIG_INDENT)    NlMtu                           = $([UInt32]$adapter.NlMtu)"
        $dscConfig += "$($global:CONFIG_INDENT)    InterfaceMetric                 = $([UInt32]$adapter.InterfaceMetric)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-NetIPInterfaceDscConfiguration

function Get-WinsServerAddressDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a WINS Server Address DSC configuration based on the local system.     
      .EXAMPLE
        Get-WinsServerAddressDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/WinsServerAddress
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()

    $netAdapters = Get-NetAdapter | Sort-Object Name
   
    foreach($adapter in $netAdapters)
    {
        $dscConfigName      = Convertto-DscConfigurationName -InputObj "$($adapter.Name) WinsServerAddress"
        $winsServerAddress  = Get-WinsClientServerStaticAddress -InterfaceAlias $($adapter.Name)
        $dscConfigAddresses = Convertto-QuotesAndCommas -InputObj $winsServerAddress

        $dscConfig += "$($global:CONFIG_INDENT)WinsServerAddress $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    InterfaceAlias = '$($dscConfigName)'"
        $dscConfig += "$($global:CONFIG_INDENT)    Address        = $($dscConfigAddresses)"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-WinsServerAddressDscConfiguration

function Get-WinsClientServerStaticAddress
{
    <#
      .SYNOPSIS
        Required function for Get-WinsServerAddressDscConfiguration
      .NOTES
        Essentially a copy/paste from NetworkingDsc in LINK.
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/blob/master/source/Modules/NetworkingDsc.Common/NetworkingDsc.Common.psm1
    #>

    [CmdletBinding()]
    [OutputType([System.String[]])]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [System.String]
        $InterfaceAlias
    )

    # Look up the interface Guid
    $adapter = Get-NetAdapter -InterfaceAlias $InterfaceAlias -ErrorAction SilentlyContinue

    if (-not $adapter)
    {
        Write-Error -Message "Adapter $($InterfaceAlias) not found for Get-WinsClientServerStaticAddress"

        # Return null to support ErrorAction Silently Continue
        return $null
    }

    $interfaceGuid = $adapter.InterfaceGuid.ToLower()

    $interfaceRegKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$interfaceGuid\"

    $interfaceInformation = Get-ItemProperty -Path $interfaceRegKeyPath -ErrorAction SilentlyContinue
    $nameServerAddressString = $interfaceInformation.NameServerList

    # Are any statically assigned addresses for this adapter?
    if (-not $nameServerAddressString)
    {
        # Static DNS Server addresses not found so return empty array
        return $null
    }
    else
    {
        return $nameServerAddressString
    }

} # end function Get-WinsClientServerStaticAddress

function Get-WinsSettingDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a WINS Setting DSC configuration based on the local system.     
      .EXAMPLE
        Get-WinsServerAddressDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/WinsSetting
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $dscConfig = @()

    # 0 equals off, 1 equals on
    $enableLmHostsRegistryKey = Get-ItemProperty `
                                    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
                                    -Name EnableLMHOSTS `
                                    -ErrorAction SilentlyContinue

    $enableLmHosts = ($enableLmHostsRegistryKey.EnableLMHOSTS -eq 1)

    # 0 equals off, 1 equals on
    $enableDnsRegistryKey = Get-ItemProperty `
                                    -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters' `
                                    -Name EnableDNS `
                                    -ErrorAction SilentlyContinue

    if ($enableDnsRegistryKey)
    {
        $enableDns = ($enableDnsRegistryKey.EnableDNS -eq 1)
    }
    else
    {
        # if the key does not exist, then set the default which is enabled.
        $enableDns = $true
    }

    $dscEnableLmHosts = Get-BooleanAsString -InputObj $enableLmHosts
    $dscEnableDns     = Get-BooleanAsString -InputObj $enableDns

    $dscConfig += "$($global:CONFIG_INDENT)WinsSetting WinsSetting"
    $dscConfig += "$($global:CONFIG_INDENT){"
    $dscConfig += "$($global:CONFIG_INDENT)    IsSingleInstance = 'Yes'"
    $dscConfig += "$($global:CONFIG_INDENT)    EnableLmHosts    = $($dscEnableLmHosts)"
    $dscConfig += "$($global:CONFIG_INDENT)    EnableDns        = $($dscEnableDns)"
    $dscConfig += "$($global:CONFIG_INDENT)}"

    return $dscConfig

} # end function Get-WinsSettingDscConfiguration

function Get-FirewallProfileDscConfiguration
{
    <#
      .SYNOPSIS
        Generates a Firewall Profile DSC configuration based on the local system.
      .EXAMPLE
        Get-FirewallProfileDscConfiguration
      .LINK
        https://github.com/dsccommunity/NetworkingDsc/wiki/FirewallProfile
    #>
    
    [OutputType([System.String[]])]
    [CmdletBinding()]
    param()

    [String[]] $profiles  = 'Domain','Public','Private'
    [String[]] $dscConfig = @()

    foreach($profile in $profiles)
    {
        $firewallProfile          = Get-NetFirewallProfile -Name $profile
        $dscConfigName            = Convertto-DscConfigurationName -InputObj "$($profile) FirewallProfile"
        $disabledInterfaceAliases = Convertto-QuotesAndCommas -InputObj $($firewallProfile.DisabledInterfaceAliases)

        if($firewallProfile.DisabledInterfaceAliases -eq 'NotConfigured')
        {
            $disabledInterfaceAliases = '@()'
            
        } else {

            $disabledInterfaceAliases = Convertto-QuotesAndCommas -InputObj $firewallProfile.DisabledInterfaceAliases
        }

        $dscConfig += "$($global:CONFIG_INDENT)FirewallProfile $($dscConfigName)"
        $dscConfig += "$($global:CONFIG_INDENT){"
        $dscConfig += "$($global:CONFIG_INDENT)    Name                            = '$($profile)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowInboundRules               = '$($firewallProfile.AllowInboundRules)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowLocalFirewallRules         = '$($firewallProfile.AllowLocalFirewallRules)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowLocalIPsecRules            = '$($firewallProfile.AllowLocalIPsecRules)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowUnicastResponseToMulticast = '$($firewallProfile.AllowUnicastResponseToMulticast)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowUserApps                   = '$($firewallProfile.AllowUserApps)'"
        $dscConfig += "$($global:CONFIG_INDENT)    AllowUserPorts                  = '$($firewallProfile.AllowUserPorts)'"
        $dscConfig += "$($global:CONFIG_INDENT)    DefaultInboundAction            = '$($firewallProfile.DefaultInboundAction)'"
        $dscConfig += "$($global:CONFIG_INDENT)    DefaultOutboundAction           = '$($firewallProfile.DefaultOutboundAction)'"
        $dscConfig += "$($global:CONFIG_INDENT)    DisabledInterfaceAliases        = $($disabledInterfaceAliases)"
        $dscConfig += "$($global:CONFIG_INDENT)    Enabled                         = '$($firewallProfile.Enabled)'"
        $dscConfig += "$($global:CONFIG_INDENT)    EnableStealthModeForIPsec       = '$($firewallProfile.EnableStealthModeForIPsec)'"
        $dscConfig += "$($global:CONFIG_INDENT)    LogAllowed                      = '$($firewallProfile.LogAllowed)'"
        $dscConfig += "$($global:CONFIG_INDENT)    LogBlocked                      = '$($firewallProfile.LogBlocked)'"
        $dscConfig += "$($global:CONFIG_INDENT)    LogFileName                     = '$($firewallProfile.LogFileName)'"
        $dscConfig += "$($global:CONFIG_INDENT)    LogIgnored                      = '$($firewallProfile.LogIgnored)'"
        $dscConfig += "$($global:CONFIG_INDENT)    LogMaxSizeKilobytes             = $($firewallProfile.LogMaxSizeKilobytes)"
        $dscConfig += "$($global:CONFIG_INDENT)    NotifyOnListen                  = '$($firewallProfile.NotifyOnListen)'"
        $dscConfig += "$($global:CONFIG_INDENT)}"
    }

    return $dscConfig

} # end function Get-FirewallProfileDscConfiguration

function Get-DscBaselineNetwork
{
    <#
      .SYNOPSIS
        Generates a Network DSC configuration based on the local system.
      .DESCRIPTION
        Excludes the following: Firewall (individual firewall rules), 
        Route, HostsFile, and anything related to NetworkTeam.
      .EXAMPLE
        Get-DscBaselineNetwork
      .EXAMPLE
        Get-DscBaselineNetwork -FilePath D:\SomeFolder\
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

    $destFile = Join-Path -Path $Folder -ChildPath 'DscBaselineNetwork.ps1'

    $dscConfig += 'Configuration DscBaselineNetwork'
    $dscConfig += '{'
    $dscConfig += "    # Generated: $(Get-Date) on $($env:COMPUTERNAME)"
    $dscConfig += '    # ref: https://github.com/dsccommunity/NetworkingDsc/wiki'
    $dscConfig += ''
    $dscConfig += '    Import-DscResource -Module NetworkingDsc'
    $dscConfig += ''
    $dscConfig += '    Node localhost'
    $dscConfig += '    {'

    $i=0

    do
    {
        switch($i)
        {
            0 { # DefaultGatewayAddress
                
                $dscConfig += Get-DefaultGatewayDscConfig
            }
            1 { # DnsClientGlobalSetting

                $dscConfig += Get-DnsClientGlobalSettingDscConfiguration
            }
            2 { # DnsConnectionSuffix

                $dscConfig += Get-DnsConnectionSuffixDscConfiguration
            }
            3 { # DnsServerAddress

                $dscConfig += Get-DnsServerAddressDscConfiguration
            }
            4 { # FirewallProfile

                $dscConfig += Get-FirewallProfileDscConfiguration
            }
            5 { # IPAddress
                
                $dscConfig += Get-IPAddressDscConfiguration
            }
            6 { # NetAdapterAdvancedProperty

                $dscConfig += Get-NetAdapterAdvancedPropertyDscConfiguration
            }
            7 { # NetAdapterBinding

                $dscConfig += Get-NetAdapterBindingDscConfiguration
            }
            8 { # NetAdapterLso

                $dscConfig += Get-NetAdapterLsoDscConfiguration
            }
            9 { # NetAdapterRdma

                $dscConfig += Get-NetAdapterRdmaDscConfiguration
            }
            10 { # NetAdapterRsc

                $dscConfig += Get-NetAdapterRscDscConfiguration
            }
            11 { # NetAdapterRss

                $dscConfig += Get-NetAdapterRssDscConfiguration
            }
            12 { # NetAdapterState

                $dscConfig += Get-NetAdapterStateDscConfiguration
            }
            13 { # NetBios

                $dscConfig += Get-NetBiosDscConfiguration
            }
            14 { # NetConnectionProfile

                $dscConfig += Get-NetConnectionProfileDscConfiguration
            }
            15 { # NetIPInterface

                $dscConfig += Get-NetIPInterfaceDscConfiguration
            }
            16 { # WinsServerAddress

                #$dscConfig += Get-WinsServerAddressDscConfiguration
            }
            17 { # WinsSetting

                $dscConfig += Get-WinsSettingDscConfiguration
            }
            default { $i = 100 }
        }

        $i++

    }while($i -lt 100)

    $dscConfig += '    }'
    $dscConfig += '}'
    $dscConfig += ''
    $dscConfig += ". DscBaselineNetwork -OutputPath $(Join-Path $Folder -ChildPath 'DscBaselineNetwork') -Verbose"
    $dscConfig += ''

    Out-File -FilePath $destFile -InputObject $dscConfig -Encoding ASCII -Force

    return $destFile

} # end function Get-DscBaselineNetwork


function Get-NetAdapterNetbiosOptionsFromRegistry
{
    <#
      .SYNOPSIS
        Returns the NetbiosOptions value for a network adapter.
      .DESCRIPTION
        Most reliable method of getting this value since network adapters
        can be in any number of states (e.g. disabled, disconnected)
        which can cause Win32 classes to not report the value.
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory = $true)]
        [ValidatePattern("^\{[a-zA-Z0-9]{8}\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{4}\-[a-zA-Z0-9]{12}\}$")]
        [System.String]
        $NetworkAdapterGUID
    )

    # Changing ErrorActionPreference variable since the switch -ErrorAction isn't supported.
    $currentErrorActionPreference = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'

    $registryParams = @{
        Name = 'NetbiosOptions'
        Path = "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($NetworkAdapterGUID)"
    }

    $registryNetbiosOptions = Get-ItemPropertyValue @registryParams

    $ErrorActionPreference = $currentErrorActionPreference

    if ($null -eq $registryNetbiosOptions)
    {
        $registryNetbiosOptions = 0
    }

    switch ($registryNetbiosOptions)
    {
        0 { return 'Default' }
        1 { return 'Enable'  }
        2 { return 'Disable' }
        default
        {
            return 'Unknown'
        }
    }
} # end function Get-NetAdapterNetbiosOptionsFromRegistry

Export-ModuleMember -Function 'Get-DscBaselineNetwork'
