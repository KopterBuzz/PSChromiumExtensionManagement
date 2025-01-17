<#
Chrome Web Store Browser Extension Management for Chromium Browsers
Currently Supports Edge and Chrome

The module uses the ExtensionSettings Policy to do its work.
https://chromeenterprise.google/policies/?policy=ExtensionSettings

Gabor Nemeth 2025
https://github.com/KopterBuzz/PSChromiumExtensionManagement

If you want to report an issue, raise an issue on Github.
If you want to contribute, fork the repo and raise a PR.
#>

#global variables to store state for supported browsers
$PSChromiumSupportedBrowsers = @{
    "Google Chrome" = [PSCustomObject]@{
        Name = "Google Chrome"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
        ExtensionSettingsName = "ExtensionSettings"
        Installed = $false
        ExtensionSettings = $null
    }
    "Microsoft Edge" = [PSCustomObject]@{
        Name = "Microsoft Edge"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Edge"
        ExtensionSettingsName = "ExtensionSettings"
        Installed = $false
        ExtensionSettings = $null
    }
    #feeling cure, might delete later.
    #(it was for debug purposes)
    "Google Ultron" = [PSCustomObject]@{
        Name = "Google Ultron"
        RegistryPath = "HKLM:\SOFTWARE\Policies\Google\Ultron"
        ExtensionSettingsName = "ExtensionSettings"
        Installed = $false
        ExtensionSettings = $null
    }
}

#evil genius trick to allow some PowerShell 5 cmdlets
$PSChromiumGetPackageSession = $null
if($PSVersionTable.PSVersion.Major -eq 7) {$PSChromiumGetPackageSession = New-PSSession -UseWindowsPowerShell}

#list of available Extension Permissions
$PSChromiumSupportedExtensionPermissions = Get-Content $((get-location).path+"\ChromiumExtensionPermissions.txt")


#to check if specific browser or browsers are installed
function Confirm-PSChromiumBrowserIsInstalled {
    Param(
        [Parameter(Mandatory)]
        [ValidateScript({$_ -in $PSChromiumSupportedBrowsers.Keys})]
        [String[]]$BrowserName 
    )
    #Get-Package doesn't work the same way on PowerShell 5 and 7 so we have to do this to maintain compatibility with both
    if ($null -ne $PSChromiumGetPackageSession) {
        return ($null -ne (Invoke-Command -ScriptBlock {param($name)Get-Package $name -ErrorAction SilentlyContinue} -ArgumentList ($BrowserName) `
                                          -Session $PSChromiumGetPackageSession))
    } else {
        return $null -ne $(Get-Package $BrowserName -ErrorAction SilentlyContinue)
    }
    
}

#run initial browser install check on module load to initialize state
$PSChromiumSupportedBrowsers.Keys | ForEach-Object {
    $PSChromiumSupportedBrowsers[$_].Installed = Confirm-PSChromiumBrowserIsInstalled -BrowserName $_
}

#used to refresh the list of extension settings in the global state
function Get-PSChromiumExtensionSettings {
Param(
    [Parameter(Mandatory)]
    [ValidateScript({$_ -in $PSChromiumSupportedBrowsers.Keys})]
    [String[]]$BrowserName
    )

    foreach ($Browser in $BrowserName) {
        $Data = $null
        $JSON = Get-ItemPropertyValue -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath `
                                      -Name $PSChromiumSupportedBrowsers[$Browser].ExtensionSettingsName `
                                      -ErrorAction SilentlyContinue

        if ($JSON) {
            $Data = $JSON | ConvertFrom-Json
            $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings = $Data
        }

    }
}
#update global state on load
Get-PSChromiumExtensionSettings -BrowserName $PSChromiumSupportedBrowsers.Keys

#install or update configuration for an extension
#you can specify a single or multiple browsers at once
function Set-PSChromiumExtension {
    Param(
        [Parameter()]
        [ValidateSet("extension","hosted_app","legacy_packaged_app","platform_app","theme","user_script")]
        [String[]]$AllowedTypes,
        [Parameter(Mandatory)]
        [ValidateScript({$_ -in $PSChromiumSupportedBrowsers.Keys})]
        [String[]]$BrowserName,
        [Parameter(Mandatory)]
        [String]$ExtensionID,
        [Parameter()]
        [ValidateScript({$_.length -le 1000})]
        [String]$BlockedInstallMessage,
        [Parameter()]
        [ValidateScript({$_ -in $PSChromiumSupportedExtensionPermissions})]
        [String]$BlockedPermissions,
        [Parameter()]
        [ValidateSet("True","False")]
        [String]$FileURLNavigationAllowed,
        [Parameter(Mandatory)]
        [ValidateSet("allowed","blocked","force_installed","normal_installed","removed")]
        [String]$InstallationMode,
        [Parameter()]
        [String]$MinimumVersionRequired,
        [Parameter()]
        [ValidateScript({[Uri]::IsWellFormedUriString($_, 'Absolute')})]
        [String]$UpdateURL,
        [Parameter()]
        [ValidateSet("True","False")]
        [String]$OverrideUpdateURL,
        [Parameter()]
        [String[]]$RuntimeAllowedHosts,
        [Parameter()]
        [String[]]$RuntimeBlockedHosts,
        [Parameter()]
        [ValidateSet("force_pinned","default_unpinned")]
        [String]$ToolbarPin
    )

    if ($ExtensionID -ne "*" -and $null -ne $AllowedTypes) {
        Write-Error $("AllowedTypes can only be used with ExtensionID = *")
        return
    }

    if ($ExtensionID -eq "*" -and $InstallationMode -in "force_installed","normal_installed") {
        Write-Error $("InstallationMode $InstallationMode is not compatible with ExtensionID $ExtensionID")
        return
    }

    #convert input into hashtable
    $ExtensionSettingsHash = @{
        blocked_install_message = $BlockedInstallMessage
        blocked_permissions = $BlockedPermissions
        file_url_navigation_allowed = $FileURLNavigationAllowed
        installation_mode = $InstallationMode
        minimum_version_required = $MinimumVersionRequired
        update_url = $UpdateURL
        override_update_url = $OverrideUpdateURL
        runtime_allowed_hosts = $RuntimeAllowedHosts
        runtime_blocked_hosts = $RuntimeBlockedHosts
        toolbar_pin = $ToolbarPin
    }

    #many fields are not mandatory, so we clean up the hashtable to keep the json tidy
    [System.Collections.Hashtable]$CleanExtensionSettingsHash =  @{}
    $ExtensionSettingsHash.Keys | ForEach-Object {
        if($ExtensionSettingsHash[$_]) {
            #there are some boolean settings, but parsing an empty input for a boolean variable will result in False which is not desirable
            #however, that would cause a problem when parsing to json
            #so all input is initially handled as string and we convert it to bool here to keep it working
            if ($ExtensionSettingsHash[$_] -in "True","False") {
                try {
                    $CleanExtensionSettingsHash[$_] = [System.Convert]::ToBoolean($ExtensionSettingsHash[$_]) 
                  } catch [FormatException] {
                    $CleanExtensionSettingsHash[$_] = $false
                  }
            } else {
                $CleanExtensionSettingsHash[$_] = $ExtensionSettingsHash[$_]
            }
        }
    }
    #creating extension setting object
    $ExtensionSettingsObject = [PSCustomObject]@{
       $ExtensionID = [PSCustomObject]$CleanExtensionSettingsHash
    }

    #inject extension setting into the specified browser(s) ExtensionSettings JSON, create the regstry paths if necessary
    foreach ($Browser in $BrowserName) {
        if (!$PSChromiumSupportedBrowsers[$Browser].Installed) {
            Write-Error $("$Browser Is Not Installed. Will not install extension.")
            Continue
        }
        try {
            Get-Iitem -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath
        } catch {
            New-Item -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath -Force
        }

        if ($null -eq $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings) {
            New-ItemProperty -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath `
                             -Name $PSChromiumSupportedBrowsers[$Browser].ExtensionSettingsName `
                             -Value ($ExtensionSettingsObject | ConvertTo-Json)
            Get-PSChromiumExtensionSettings -BrowserName $PSChromiumSupportedBrowsers.Keys
            return
        } 

        if ($PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.$ExtensionID) {
            $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.$ExtensionID = $ExtensionSettingsObject.$ExtensionID
        } else {
            $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings | Add-Member -MemberType NoteProperty `
                                                    -Name $ExtensionID `
                                                    -Value $ExtensionSettingsObject.$ExtensionID -Force
        }
        Set-ItemProperty -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath `
                         -Name $PSChromiumSupportedBrowsers[$Browser].ExtensionSettingsName `
                         -Value ($PSChromiumSupportedBrowsers[$Browser].ExtensionSettings | ConvertTo-Json) -Force

    }
    Get-PSChromiumExtensionSettings -BrowserName $PSChromiumSupportedBrowsers.Keys
}

function Remove-PSChromiumExtension {
    Param(
        [Parameter(Mandatory)]
        [ValidateScript({$_ -in $PSChromiumSupportedBrowsers.Keys})]
        [String[]]$BrowserName,
        [Parameter(Mandatory)]
        [String[]]$ExtensionID
    )
    foreach ($Browser in $BrowserName) {
        if ($PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.$ExtensionID) {
            Set-ItemProperty -Path $PSChromiumSupportedBrowsers[$Browser].RegistryPath `
            -Name $PSChromiumSupportedBrowsers[$Browser].ExtensionSettingsName `
            -Value ($PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.PSObject.Properties.Remove($ExtensionID) | ConvertTo-Json) -Force
        }
    }
    Get-PSChromiumExtensionSettings -BrowserName $PSChromiumSupportedBrowsers.Keys
}

#retrieve extension settings outside the context of $PSChromiumSupportedBrowsers
function Get-PSChromiumExtension {
    Param(
        [Parameter(Mandatory)]
        [ValidateScript({$validateset = $PSChromiumSupportedBrowsers.Keys;$validateset+="All";$_ -in $validateset})]
        [String[]]$BrowserName,
        [Parameter(Mandatory)]
        [String[]]$ExtensionID,
        [Parameter()]
        [switch]$AsJSON
    )
    
    if ($BrowserName -eq "All") {$BrowserName = $PSChromiumSupportedBrowsers.Keys}
    $Output = [System.Collections.Generic.List[PSObject]]@()
    foreach ($Browser in $BrowserName) {
        if (!$PSChromiumSupportedBrowsers[$Browser].Installed) {
            Write-Error $("$Browser Is Not Installed.")
            Continue
        }
        if ($ExtensionID -eq "All") {
            $obj = [PSCustomObject]@{
                Browser = $Browser
                ExtensionSettings = $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings
            }
            if ($AsJSON) {$obj.ExtensionSettings = $obj.ExtensionSettings | ConvertTo-Json -Depth 10}
            [void]$Output.Add($obj)
            remove-variable obj
            Continue
        }
        if ($PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.$ExtensionID) {
            $obj = [PSCustomObject]@{
                Browser = $Browser
                ExtensionSettings = $PSChromiumSupportedBrowsers[$Browser].ExtensionSettings.$ExtensionID
            }
            if ($AsJSON) {$obj.ExtensionSettings = $obj.ExtensionSettings | ConvertTo-Json -Depth 10}
            [void]$Output.Add($obj)
            remove-variable obj
        }
    }
    return $Output
}