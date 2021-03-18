# DscBaseline #

Creates DSC configurations based on the configuration of the current system.


## Description ##

This PowerShell module was created to expedite the adoption of Microsoft Desired State Configuration (DSC) for configuration management. Building these configuration files by hand takes far too long and lacks the benfits of a programmatic solution. DscBaseline covers common DSC modules and creates configuration files based on the system where it is launched. The configuration node is specified as `localhost` allowing it to be applied to any other systems. Making it useful for:
 - backing up system configuration
 - upgrading a system
 - scaling out (horizontal)
 - adopting Configuration As Code (CAC) methodologies
 - disaster recovery documentation


## Warning ##

The resulting configuration files ***must*** be reviewed and tested before use in production. The following are just two examples of why this is important. For more, see Known Issues further below.

1. The DSC configuration produced for Windows Services includes a number of services having a locally unique ID (LUID) which is regenerated on restart. So while these entries will exist in the DSC configuration, they will do nothing since the services will have a new LUID after reboot. 

2. Applying DscBaseline created network configurations to a system without modification may produce duplicate IP address errors, network instability, and/or rendor the system inaccessible. Be sure to update the network settings as necessary and have a way to get console access.


## Coverage ##

DscBaseline produces configurations for the following.

1. Security Policy - Account Policy ([SecurityPolicyDsc](https://github.com/dsccommunity/SecurityPolicyDsc))
2. Security Policy - Security Option ([SecurityPolicyDsc](https://github.com/dsccommunity/SecurityPolicyDsc))
3. Security Policy - User Rights Assignment ([SecurityPolicyDsc](https://github.com/dsccommunity/SecurityPolicyDsc))
4. Audit Policy ([AuditPolicyDsc](https://github.com/dsccommunity/AuditPolicyDsc))
5. Network ([NetworkingDsc](https://github.com/dsccommunity/NetworkingDsc/))
6. Services ([PSDscResources](https://github.com/PowerShell/PSDscResources))
7. *Group Policy - *EXPERIMENTAL*. See known issues for details. ([PSDscResources](https://github.com/PowerShell/PSDscResources))


## Known Issues ##

| FILE | ISSUE |
| ---- | ----- |
| DscBaselineServices.ps1 | Services with locally unique IDs (LUID) are included in the resulting configuration files. These should be removed since the LUID will regenerate on restart making the entries unnecessary. More info: [Per-user services in Windows 10 and Windows Server](https://docs.microsoft.com/en-us/windows/application-management/per-user-services-in-windows) |
| DscBaselineServices.ps1 | Only services with 'Start=Disabled' will have 'State=Stopped'. Services set to 'Automatic' and 'Manual' are configured as 'State=Ignore' regardless of how the host is configured to ensure processes are allowed to run. |
| DscBaselineSecurityOption.ps1 | Configurations with no value may produce errors and are commented out. |
| DscBaselineNetwork.ps1 | NetAdapterAdvancedProperty is restricted to a subset of properties since additional settings may cause errors. |
| DscBaselineNetwork.ps1 | DSC_NetBios errors when configuring adapters in different states. Fix is pending [PR 479](https://github.com/dsccommunity/NetworkingDsc/pull/479). |
| DscBaselineNetwork.ps1 | The following are ***excluded***: NetTeam, NetTeamInterface, WaitForNetworkTeam, Route, HostsFile, NetAdapterName, Firewall |
| DscBaselineNetwork.ps1 | Configuration overlap exists between NetAdapterLso and NetAdapterAdvancedProperty. Fix via [PR 481](https://github.com/dsccommunity/NetworkingDsc/pull/481). DscBaseline omits overlapped configuration from NetAdapterLso. |
| DscBaselineGroupPolicy.ps1 | This functionality is purely experimental and not inclusive of all possible GPO settings. It was abandoned after hearing of Microsoft making significant progress in this area. That said, the Group Policy logic remains in this module and can be invoked using the `-TryGroupPolicy` switch. It attempts to extract registry configurations produced by `gpresult.exe /scope computer /Z` and will create a registry DSC configuration based on PsDscResources. Note that an elevated command prompt should be used and it works best on non-domain-joined systems. |


## Getting Started ##

A tutorial is available at the following URL:

https://phbits.medium.com/creating-dsc-configurations-with-dscbaseline-ae4ec34567b1
