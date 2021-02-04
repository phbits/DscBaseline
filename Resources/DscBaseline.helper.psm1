
[string] $global:CONFIG_INDENT = '        '

function Convertto-QuotesAndCommas
{
    <#
      .SYNOPSIS
        Converts array or string into single-quoted and comma delimited string.
      .EXAMPLE
        Convertto-QuotesAndCommas -InputObj $IpAddressArray
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        # string or array
        $InputObj
    )

    [string]$quoteCommaString = "`'`'"

    if($null -ne $InputObj)
    {
        if($InputObj -is [array])
        {
            if($InputObj.Count -gt 1)
            {
                $quoteCommaString = "`'$($InputObj -Join "`',`'")`'"

            } else {

                $quoteCommaString = "`'$($InputObj[0])`'"
            }
        } else {
    
            if([System.String]::IsNullOrEmpty($InputObj) -eq $false)
            {
                $quoteCommaString = "`'$($InputObj)`'"
            }
        }
    }

    return $quoteCommaString

} # end function Convertto-QuotesAndCommas

function Convertto-DscConfigurationName
{
    <#
      .SYNOPSIS
        Converts string into DSC configuration name.
      .EXAMPLE
        Convertto-DscConfigurationName -InputObj 'Ethernet 0 *RSS'
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [Parameter(Mandatory=$true)]
        [System.String]
        # string or array
        $InputObj
        ,
        [Parameter(Mandatory=$false)]
        [int]
        # max length
        $MaxLength = 70
    )

    $dscName = ''
    $regex   = "^[A-Za-z0-9_]{1,$($MaxLength)}$"

    if($InputObj -notmatch $regex)
    {
        $inputObjArray = $InputObj.ToCharArray()

        if($inputObjArray.Length -lt $MaxLength)
        {
            $MaxLength = $inputObjArray.Length
        }

        for($i = 0; $i -lt $MaxLength; $i++)
        {
            if($inputObjArray[$i] -match "^[a-zA-Z0-9_]{1}$")
            {
                $dscName += $inputObjArray[$i]

            } else {
                
                # replace character with underscore
                $dscName += '_'
            }
        }
    
        $dscName = $dscName.Replace('__','_')

    } else {

        return $InputObj
    }

    return $dscName.Replace('__','_')

} # end function Convertto-DscConfigurationName

function Get-BooleanAsString
{
    <#
      .SYNOPSIS
        Converts boolean value to string.
    #>
    [OutputType([System.String])]
    [CmdletBinding()]
    param
    (
        [parameter(Mandatory=$true)]
        [AllowNull()]
        [AllowEmptyString()]
        # string or array
        $InputObj
    )

    $returnBoolString = ''

    if($null -ne $InputObj)
    {
        $returnBoolString = '$false'

        if($InputObj -is [boolean])
        {
            if($InputObj -eq $true)
            {
                $returnBoolString = '$true'
            }
        }
        
        if($InputObj -is [string])
        {
            if($InputObj.Trim().ToLower().Contains('true'))
            {
                $returnBoolString = '$true'
            }
        }
    }

    return $returnBoolString

} # end function Get-BooleanAsString

Export-ModuleMember -Function "*"
