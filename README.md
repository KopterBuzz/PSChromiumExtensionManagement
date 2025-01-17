# PSChromiumExtensionManagement
PowerShell module to manage Chromium Extensions

I wanted a granular way to manage extension deployments. GPO/Intune policy wasn't cutting it.

I couldn't find a better method, so wrote a module.

It uses the ExtensionSettings policy. Relevant material:
https://www.chromium.org/administrators/policy-list-3/extension-settings-full/

https://support.google.com/chrome/a/answer/9867568?hl=en&ref_topic=9023098&sjid=12833412561403747602-EU

Only supports Windows.

Compatible with PowerShell 5 and 7.

Currently supports Chrome and Edge.

It only works with Edge if the computer is "Managed by Organization" e.g. Entra or Domain joined.

The cmdlets do what the comments say but I will probably create better documentation as time goes on.