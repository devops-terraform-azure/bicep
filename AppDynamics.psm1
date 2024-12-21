# Appdynamics .NET agent management PowerShell module
# Version: 1.5.4
# Release date: 7 Nov 2017
# Author: Alex Fedotyev @ AppDynamics Inc. (afedotyev@appdynamics.com)
# Thiru Chidambaram @ AppDynamics Inc.,

# ------------------------------------------------------------------------------------------
#  Shared functions - private per this module
# ------------------------------------------------------------------------------------------

function Get-AgentShared
{
    Write-Verbose "Reading current .NET agent version from registry."
    $ProductName="AppDynamics .NET Agent"
    $agent=Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where {$_.DisplayName -eq "$ProductName" } | Select-Object PSChildName, DisplayVersion
    return $agent
}


function Restart-CoordinatorShared()
{
    $agent = Get-AgentShared
    if($agent -ne $null) { Restart-Service AppDynamics.Agent.Coordinator_service }
}


function Stop-ApplicationShared([Bool] $RestartIIS, [String[]] $RestartWindowsServices)
{
    if($RestartIIS)
    {
        if(Get-Command "iisreset.exe" -ErrorAction SilentlyContinue)
        {
            iisreset.exe /stop | Out-Null
        }
    }

    if($RestartWindowsServices -ne $null) { 
        Stop-Service $RestartWindowsServices -ErrorAction SilentlyContinue
        Get-Service $RestartWindowsServices -ErrorAction SilentlyContinue | ForEach-Object { if(($_ -ne $null) -and ($_.Status -ne "Stopped")) { $_.WaitForStatus("Stopped") } }
    }
}


function Start-ApplicationShared([Bool] $RestartIIS, [String[]] $RestartWindowsServices)
{
    if($RestartIIS)
    {
        if(Get-Command "iisreset.exe" -ErrorAction SilentlyContinue)
        {
            iisreset.exe /start | Out-Null
        }
    }

    if($RestartWindowsServices -ne $null) { Start-Service $RestartWindowsServices -ErrorAction SilentlyContinue }
}


function Restart-ApplicationShared([Bool] $RestartIIS, [String[]] $RestartWindowsServices)
{
    if($RestartIIS)
    {
        if(Get-Command "iisreset.exe" -ErrorAction SilentlyContinue)
        {
            iisreset.exe | Out-Null
        }
    }

    if($RestartWindowsServices -ne $null) { Restart-Service $RestartWindowsServices -ErrorAction SilentlyContinue }
}


function Execute-CommandShared([String] $Filename, [String] $Arguments)
{
    if(-Not $Filename.StartsWith('"')) { $Filename = '"'+$Filename+'"' }

    $ps = new-object System.Diagnostics.Process
    $ps.StartInfo.Filename = $Filename
    $ps.StartInfo.Arguments = $Arguments
    $ps.StartInfo.UseShellExecute = $false
    [void]$ps.Start()
    [void]$ps.WaitForExit()
    $exitcode = $ps.ExitCode
    return $exitcode
}


function Uninstall-AgentShared
{
    Write-Verbose "Uninstalling existing agent."
    $agent = Get-AgentShared
    if($agent -ne $null)
    {
        $filename = "$env:systemroot\system32\msiexec.exe"
        $arguments = " /x " + $agent.PSChildName + " /q /norestart"
        $logpath = $env:Temp + '\AppDynamicsUninstall.log'
        $arguments += ' /L*v "' + $logpath + '"'
        $exitcode = Execute-CommandShared $filename $arguments
        return $exitcode
    }
    else { return 0 }
}

##########Registry Change Start##############################
function RegistryChanges-Shared ([Bool] $SharePointInstall)
{
   
     $currentLocation = Get-Location
     
     if( $SharePointInstall)
     {
          Write-Verbose "SharePoint installation. Adding LoaderOptimization setting to the Regitry."
          Set-Location HKLM:\SOFTWARE\Microsoft\.NETFramework
          try 
            {
                Get-ItemProperty -Path . | Select-Object -ExpandProperty LoaderOptimization -ErrorAction Stop | Out-Null
                Set-ItemProperty -Path . -Name LoaderOptimization -Value 1
            }

          catch 
            {
                New-ItemProperty -Path . -Name LoaderOptimization -Value 1 -PropertyType "DWORD"
            }

          Set-Location HKLM:\SOFTWARE\Wow6432Node\Microsoft\.NETFramework
          try 
            {
                Get-ItemProperty -Path . | Select-Object -ExpandProperty LoaderOptimization -ErrorAction Stop | Out-Null
                Set-ItemProperty -Path . -Name LoaderOptimization -Value 1
            }

          catch 
            {
                New-ItemProperty -Path . -Name LoaderOptimization -Value 1 -PropertyType "DWORD"
            }
          
     }

     Set-Location $currentLocation
}


function Test-RegistryValue {
param (
         [parameter(Mandatory=$true)]
         [ValidateNotNullOrEmpty()]$Path,

        [parameter(Mandatory=$true)]
         [ValidateNotNullOrEmpty()]$Value
       )

    try 
        {
            Get-ItemProperty -Path $Path | Select-Object -ExpandProperty $Value -ErrorAction Stop | Out-Null
            return $true
        }

    catch 
        {
            return $false
        }
}
##########Registry Change End##############################

function Install-AgentShared([String] $setup_file, [String] $template_file, [Hashtable]$arguments)
{
    Write-Verbose "Installing .NET agent."
    $setup_path = Resolve-Path $setup_file

    $filename = "$env:systemroot\system32\msiexec.exe"
    $params = ' /i "' + $setup_path +'" /q /norestart'
    
    #verbose MSIEXEC logging
    #if(Get-VerboseShared)
    #{

        $logpath = $env:Temp + '\AppDynamicsInstall.log'
        $params += ' /L*v "' + $logpath + '"'

    #}

    if(-Not [string]::IsNullOrEmpty($template_file))
    {
        $template_path = Resolve-Path $template_file
        $params += ' AD_SetupFile="'+$template_path+'"'
    }

    # Serialize optional parameters to the arguments list for the MSIEXEC
    if($arguments -ne $null)
    {
        Foreach($key in $arguments.Keys)
        {
            $params += " " + $key + "=""" + $arguments.$key.ToString() + """"
        }
    }

    $exitcode = Execute-CommandShared $filename $params

    return $exitcode
}

function Get-VerboseShared()
{
    $verbose = $PSCmdlet.MyInvocation.BoundParameters["Verbose"].IsPresent
    if($verbose -eq $null) { $verbose = $false }
    return $verbose
}

function Get-64ArchitectureShared()
{
    Write-Verbose "Checking OS architecture"
    $architecture = Get-WmiObject -Class Win32_OperatingSystem | Select-Object OSArchitecture
    return $architecture.OSArchitecture -eq "64-bit"
}


function Get-MsiProductVersionShared($filePath)
{

    function Get-MsiProductVersionInternal {
 
        [CmdletBinding()]
        param (
            [Parameter(Mandatory=$true)]
            [ValidateScript({$_ | Test-Path -PathType Leaf})]
            [string]
            $Path
        )
    
		$file = (Resolve-Path $Path).Path
		
        $windowsInstaller = New-Object -com WindowsInstaller.Installer

        $database = $windowsInstaller.GetType().InvokeMember(
                "OpenDatabase", "InvokeMethod", $Null, 
                $windowsInstaller, @($file, 0)
            )

        $q = "SELECT Value FROM Property WHERE Property = 'ProductVersion'"
        $view = $database.GetType().InvokeMember(
                "OpenView", "InvokeMethod", $Null, $database, ($q)
            )

        [void]$view.GetType().InvokeMember("Execute", "InvokeMethod", $Null, $view, $Null)

        $record = $view.GetType().InvokeMember(
                "Fetch", "InvokeMethod", $Null, $view, $Null
            )

        $productVersion = $record.GetType().InvokeMember(
                "StringData", "GetProperty", $Null, $record, 1
            )

        [void]$view.GetType().InvokeMember("Close", "InvokeMethod", $Null, $view, $Null)

		Remove-Variable -Name record, view, database, windowsInstaller

        return $productVersion
    }

    Write-Verbose "Reading msi file version."

    $version = Get-MsiProductVersionInternal($filePath)
    return [version]$version

}


# Add executable for monitoring and saves to the config.xml
function Add-ExecutableMonitoringShared([ARRAY]$applications, [BOOL]$override)
{
    Write-Verbose "Adding executable for monitoring"
    $configFile = "$env:ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    $configXml = [xml](Get-Content $configFile)

    $agent = $configXml.SelectSingleNode("//appdynamics-agent")

    $appAgents = $agent.SelectSingleNode("app-agents")
    if($appAgents -eq $null)
    {
        $appAgents = $configXml.CreateElement("app-agents")
        [void]$agent.AppendChild($appAgents)
    }

    $apps = $appAgents.SelectSingleNode("standalone-applications")
    if($apps -eq $null)
    {
        $apps = $configXml.CreateElement("standalone-applications")
        [void]$appAgents.AppendChild($apps)
    }

    # Delete any existing applications from monitoring
    if($override)
    {
        $apps.RemoveAll()
    }

    # Add all applications to the configuration
    foreach($application in $applications)
    {
        $executable = $application.Name
        $tier = $application.Tier

        $app = $apps.SelectSingleNode("standalone-application[translate(@executable, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=translate('$executable', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')]")
        if($app -eq $null)
        {
            # create new application
            $app = $configXml.CreateElement("standalone-application")
            [void]$apps.AppendChild($app)

            $appAttribute = $configXml.CreateAttribute("executable")
            $appAttribute.Value = $executable
            [void]$app.Attributes.Append($appAttribute)

            $tierName = $configXml.CreateElement("tier")
            [void]$app.AppendChild($tierName)

            $nameAttribute = $configXml.CreateAttribute("name")
            $nameAttribute.Value = $tier
            [void]$tierName.Attributes.Append($nameAttribute)
        }
        else
        {
            # Modify exiting application - change the tier name
            $tierName = $app.SelectSingleNode("tier")
            if($tierName -eq $null)
            {
                $tierName = $configXml.CreateElement("tier")
                [void]$app.AppendChild($tierName)

                $nameAttribute = $configXml.CreateAttribute("name")
                $nameAttribute.Value = $tier
                [void]$tierName.Attributes.Append($nameAttribute)
            }
            else
            {
                if($tierName.Attributes.GetNamedItem("name") -ne $null)
                {
                    $tierName.Attributes["name"].Value = $tier
                }
                else
                {
                    $nameAttribute = $configXml.CreateAttribute("name")
                    $nameAttribute.Value = $tier
                    [void]$tierName.Attributes.Append($nameAttribute)
                }
            }
        }
    }
    $configXml.Save($configFile)
}



# Add windows service for monitoring and saves to the config.xml
function Add-WindowsServiceMonitoringShared([ARRAY]$applications, [BOOL]$override)
{
    Write-Verbose "Adding windows service for monitoring"
    $configFile = "$env:ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    $configXml = [xml](Get-Content $configFile)

    $agent = $configXml.SelectSingleNode("//appdynamics-agent")

    $appAgents = $agent.SelectSingleNode("app-agents")
    if($appAgents -eq $null)
    {
        $appAgents = $configXml.CreateElement("app-agents")
        [void]$agent.AppendChild($appAgents)
    }

    $apps = $appAgents.SelectSingleNode("windows-services")
    if($apps -eq $null)
    {
        $apps = $configXml.CreateElement("windows-services")
        [void]$appAgents.AppendChild($apps)
    }

    # Delete any existing applications from monitoring
    if($override)
    {
        $apps.RemoveAll()
    }

    # Add all applications to the configuration
    foreach($application in $applications)
    {
        $service = $application.Name
        $tier = $application.Tier

        $app = $apps.SelectSingleNode("windows-service[translate(@executable, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=translate('$executable', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')]")
        if($app -eq $null)
        {
            # create new application
            $app = $configXml.CreateElement("windows-service")
            [void]$apps.AppendChild($app)

            $appAttribute = $configXml.CreateAttribute("name")
            $appAttribute.Value = $service
            [void]$app.Attributes.Append($appAttribute)

            $tierName = $configXml.CreateElement("tier")
            [void]$app.AppendChild($tierName)

            $nameAttribute = $configXml.CreateAttribute("name")
            $nameAttribute.Value = $tier
            [void]$tierName.Attributes.Append($nameAttribute)
        }
        else
        {
            # Modify exiting application - change the tier name
            $tierName = $app.SelectSingleNode("tier")
            if($tierName -eq $null)
            {
                $tierName = $configXml.CreateElement("tier")
                [void]$app.AppendChild($tierName)

                $nameAttribute = $configXml.CreateAttribute("name")
                $nameAttribute.Value = $tier
                [void]$tierName.Attributes.Append($nameAttribute)
            }
            else
            {
                if($tierName.Attributes.GetNamedItem("name") -ne $null)
                {
                    $tierName.Attributes["name"].Value = $tier
                }
                else
                {
                    $nameAttribute = $configXml.CreateAttribute("name")
                    $nameAttribute.Value = $tier
                    [void]$tierName.Attributes.Append($nameAttribute)
                }
            }
        }
    }

    $configXml.Save($configFile)
}



# Add executable for monitoring and saves to the config.xml
function Add-IISApplicationMonitoringShared([ARRAY]$applications, [BOOL]$override)
{
    Write-Verbose "Adding executable for monitoring"
    $configFile = "$env:ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    $configXml = [xml](Get-Content $configFile)

    $agent = $configXml.SelectSingleNode("//appdynamics-agent")

    $appAgents = $agent.SelectSingleNode("app-agents")
    if($appAgents -eq $null)
    {
        $appAgents = $configXml.CreateElement("app-agents")
        [void]$agent.AppendChild($appAgents)
    }

    $IIS = $appAgents.SelectSingleNode("IIS")
    if($IIS -eq $null)
    {
        $IIS = $configXml.CreateElement("IIS")
        [void]$appAgents.AppendChild($IIS)
    }

    $apps = $IIS.SelectSingleNode("applications")
    if($apps -eq $null)
    {
        $apps = $configXml.CreateElement("applications")
        [void]$IIS.AppendChild($apps)
    }

    # Delete any existing applications from monitoring
    if($override)
    {
        $apps.RemoveAll()
    }

    # Add all applications to the configuration
    foreach($application in $applications)
    {
        $site = $application.Site
        $path = $application.Path
        $tier = $application.Tier

        $app = $apps.SelectSingleNode("application[translate(@site, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=translate('$site', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz') and translate(@path, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')=translate('$path', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')]")
        if($app -eq $null)
        {
            # create new application
            $app = $configXml.CreateElement("application")
            [void]$apps.AppendChild($app)

            $appAttribute = $configXml.CreateAttribute("site")
            $appAttribute.Value = $site
            [void]$app.Attributes.Append($appAttribute)

            $appAttribute1 = $configXml.CreateAttribute("path")
            $appAttribute1.Value = $path
            [void]$app.Attributes.Append($appAttribute1)

            $tierName = $configXml.CreateElement("tier")
            [void]$app.AppendChild($tierName)

            $nameAttribute = $configXml.CreateAttribute("name")
            $nameAttribute.Value = $tier
            [void]$tierName.Attributes.Append($nameAttribute)
        }
        else
        {
            # Modify exiting application - change the tier name
            $tierName = $app.SelectSingleNode("tier")
            if($tierName -eq $null)
            {
                $tierName = $configXml.CreateElement("tier")
                [void]$app.AppendChild($tierName)

                $nameAttribute = $configXml.CreateAttribute("name")
                $nameAttribute.Value = $tier
                [void]$tierName.Attributes.Append($nameAttribute)
            }
            else
            {
                if($tierName.Attributes.GetNamedItem("name") -ne $null)
                {
                    $tierName.Attributes["name"].Value = $tier
                }
                else
                {
                    $nameAttribute = $configXml.CreateAttribute("name")
                    $nameAttribute.Value = $tier
                    [void]$tierName.Attributes.Append($nameAttribute)
                }
            }
        }
    }

    $configXml.Save($configFile)
}




function Update-AgentConfigurationShared([STRING] $HostName, [STRING] $Port, [STRING] $SSL, [STRING] $Application, [STRING] $AccountName, [STRING] $AccessKey, [STRING] $ConfigPath)
{
    Write-Verbose "Adding executable for monitoring"
    #changed below two lines for https://jira.corp.appdynamics.com/browse/CES-646
    #$configFile = "$env:ProgramData\AppDynamics\DotNetAgent\Config\config.xml"
    $configFile = (Get-ItemProperty "hklm:\SOFTWARE\AppDynamics\dotNet Agent" -Name DotNetAgentFolder).DotNetAgentFolder+"Config\config.xml"
    $configXml = [xml](Get-Content $configFile)

    $agent = $configXml.SelectSingleNode("//appdynamics-agent")

    $controller = $agent.SelectSingleNode("controller")
    if($controller -eq $null)
    {
        $controller = $configXml.CreateElement("controller")
        [void]$agent.AppendChild($controller)
    }

    if(-not ([STRING]::IsNullOrEmpty($HostName)))
    {
        if($controller.Attributes.GetNamedItem("host") -ne $null)
        {
            $controller.Attributes["host"].Value = $HostName
        }
        else
        {
            $hostAttribute = $configXml.CreateAttribute("host")
            $hostAttribute.Value = $HostName
            [void]$controller.Attributes.Append($hostAttribute)
        }
    }

    if(-not ([STRING]::IsNullOrEmpty($Port)))
    {
        if($controller.Attributes.GetNamedItem("port") -ne $null)
        {
            $controller.Attributes["port"].Value = $Port
        }
        else
        {
            $portAttribute = $configXml.CreateAttribute("port")
            $portAttribute.Value = $Port
            [void]$controller.Attributes.Append($portAttribute)
        }
    }

    if(-not ([STRING]::IsNullOrEmpty($SSL)))
    {
        if($controller.Attributes.GetNamedItem("ssl") -ne $null)
        {
            $controller.Attributes["ssl"].Value = $SSL
        }
        else
        {
            $sslAttribute = $configXml.CreateAttribute("ssl")
            $sslAttribute.Value = $SSL
            [void]$controller.Attributes.Append($sslAttribute)
        }
    }

    if(-not ([STRING]::IsNullOrEmpty($Application)))
    {
        $app = $controller.SelectSingleNode("application")
        if($app -eq $null)
        {
            $app = $configXml.CreateElement("application")
            [void]$controller.AppendChild($app)
        }

        if($app.Attributes.GetNamedItem("name") -ne $null)
        {
            $app.Attributes["name"].Value = $Application
        }
        else
        {
            $nameAttribute = $configXml.CreateAttribute("name")
            $nameAttribute.Value = $Application
            [void]$app.Attributes.Append($nameAttribute)
        }
    }

    if((-not ([STRING]::IsNullOrEmpty($AccountName))) -or (-not ([STRING]::IsNullOrEmpty($AccessKey))))
    {
        $account = $controller.SelectSingleNode("account")
        if($account -eq $null)
        {
            $account = $configXml.CreateElement("account")
            [void]$controller.AppendChild($account)
        }

        if(-not ([STRING]::IsNullOrEmpty($AccountName)))
        {
            if($account.Attributes.GetNamedItem("name") -ne $null)
            {
                $account.Attributes["name"].Value = $AccountName
            }
            else
            {
                $nameAttribute = $configXml.CreateAttribute("name")
                $nameAttribute.Value = $AccountName
                [void]$account.Attributes.Append($nameAttribute)
            }
        }

        if(-not ([STRING]::IsNullOrEmpty($AccessKey)))
        {
            if($account.Attributes.GetNamedItem("password") -ne $null)
            {
                $account.Attributes["password"].Value = $AccessKey
            }
            else
            {
                $pwdAttribute = $configXml.CreateAttribute("password")
                $pwdAttribute.Value = $AccessKey
                [void]$account.Attributes.Append($pwdAttribute)
            }
        }
    }

    $configXml.Save($configFile)
}




# Exports function code including all shared functions into one ScriptBlock for remote execution
function Get-CodeInternal($Command, $CustomCommand = $null)
{
    $code = "PARAM("
    $params = ""

    foreach($p in $Command.Parameters.Keys)
    {
        $code += '['+$Command.Parameters[$p].ParameterType+']$'+$p+','
        $params += ' $'+$p
    }
    
    if($code.EndsWith(',')) { $code = $code.TrimEnd(','.ToCharArray()) }
    if($params.EndsWith(',')) { $params = $params.TrimEnd(','.ToCharArray()) }

    $code += ")"
    $code += [Environment]::NewLine

    # Include all shared commands from the module into the script for remote execution
    $module = $MyInvocation.MyCommand.ModuleName
    $functions = Get-Command -All -Type Function -Module $module | Where { $_.Name.EndsWith("Shared") }

    # Add custom command into the collection
    if($CustomCommand -ne $null)
    {
        $functions = $functions + $CustomCommand
    }

    foreach($f in $functions)
    { 
        $code += "function $f {"
        $code += (Get-Command $f).Definition
        $code += "}"
        $code += [Environment]::NewLine
    }
    
    # Prepare the command definition
    $code += "function $Command {"
    $code += $Command.Definition
    $code += "}"
    $code += [Environment]::NewLine

    $code += $Command.Name
    $code += $params


    return [ScriptBlock]::Create($code)
}


function Copy-FilesToRemoteComputersInternal([string[]] $Files, [string[]] $Computers, [string] $Share)
{
    Write-Verbose "Copying files to a remote share."
    foreach($computer in $Computers)
    {
        if(Test-Connection $computer)
        {
            $remote_folder = "\\$computer\$Share"
            New-Item -ItemType Directory -Path $remote_folder -Force | Out-Null
            Copy-Item -Path $files -Destination $remote_folder -Force
        }
    }
}



Function Test-IsAdminInternal
{
	If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
	    [Security.Principal.WindowsBuiltInRole] "Administrator"))
	{
	    Write-Warning "You do not have Administrator rights to run this module!`nPlease re-run this script as an Administrator (Run as Administrator)!"
	    Break
	}
}



Function Test-PowerShellVersionInternal
{
    # If version is less than 3.0 give a warning
    if($PSVersionTable.PSVersion.Major -lt 3)
    {
        Write-Warning "Current script requires PowerShell version 3.0 or later.`nPlease upgrade the PowerShell and re-run this script."
	    Break
    }
}

Function Test-ComputerConnection([string[]] $Computers)
{
  foreach($computer in $Computers)
  {
     if(!(Test-Connection $computer))
        {
            Write-Warning "$computer Connection failed"
            return $false
        }
        else
        {
           return $true
        }
  
  }

}

function Download-AgentLogs([STRING]$computer, [STRING] $sourcedirectory,[STRING] $targetdirectory)
{
   $OSversion =(Get-WmiObject Win32_OperatingSystem).Name
   if ($computer -eq $null)
    {
      if($OSversion -contains 2003)
        {
        Write-Host $OSversion
        #$sourcedirectory = "$env:AppData\AppDynamics\DotNetAgent\*"
        $sourcedirectory = "C:\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
        Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
        Write-Host "Copied files successfully to" $targetdirectory
        }
        else
        {
        Write-Host $OSversion
        #$sourcedirectory = "C:\ProgramData\AppDynamics\DotNetAgent\*" 
        $sourcedirectory = "$env:ProgramData\AppDynamics\DotNetAgent\*" 
        Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
        Write-Host "Copied files successfully to" $targetdirectory
        
        }
        
    }
    else
    {
        if($OSversion -contains 2003)
        {
        Write-Host $OSversion            
        $sourcedirectory = "\\$ComputerName\C$\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
        Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
        Write-Host "Copied files successfully to" $targetdirectory
        }
        else
        {
        Write-Host $OSversion            
        $sourcedirectory = "\\$ComputerName\C$\ProgramData\AppDynamics\DotNetAgent\*"  
        #$sourcedirectory = "\\$ComputerName\$env:ProgramData\AppDynamics\DotNetAgent\*"  
        Write-Host $sourcedirectory
        Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
        Write-Host "Copied files successfully to" $targetdirectory
        }
    }
    
}
<#Function Ask-Confirm([string] $ServiceName)
{
	 $title="Confirm"
     $message="Are you sure you want to start the service $ServiceName ?"

	$choiceYes = New-Object System.Management.Automation.Host.ChoiceDescription "&Yes", "Answer Yes."
	$choiceNo = New-Object System.Management.Automation.Host.ChoiceDescription "&No", "Answer No."
	$options = [System.Management.Automation.Host.ChoiceDescription[]]($choiceYes, $choiceNo)
	$result = $host.ui.PromptForChoice($title, $message, $options, 1)
	switch ($result)
    {
		0 
		{
            Write-Host "Hello True"   
		Return $true
		}
 
		1 
		{
        Write-Host "Hello False"
		Return $false
		}
	}
}#>

# ------------------------------------------------------------------------------------------
#  Comanndlets - available to end users
# ------------------------------------------------------------------------------------------

<#
.Synopsis
   Verifies the agent version 

.DESCRIPTION
   This script will verify version of agent installed on the machine

.PARAMETER  ComputerName
  This is the optional parameter for this function. If you pass the value for computer name,it will display the version of the agent installed on that machine

#>
function global:Get-Agent
{
	[CmdletBinding()]
	PARAM(
		[Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null
	)

    process{
	    function Get-AgentLocal()
	    {
            $agent=Get-AgentShared
	        $version = $null
	        if($agent -ne $null) { $version = [Version]$agent.DisplayVersion }
            else { [version] "0.0.0.0" }
            $version 
	    }

	    #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
          
            foreach($computer in $ComputerName)
            {
                 $Result =  Test-ComputerConnection($computer)
                if($Result)
                {
                     $verbose = Get-VerboseShared
                     $code = Get-CodeInternal(Get-Command Get-AgentLocal)
                     Invoke-Command -ComputerName $computer -ScriptBlock $code -Verbose:$verbose | select -ExcludeProperty RunspaceId
                                                        
                }
            }
            #$verbose = Get-VerboseShared

		    #$code = Get-CodeInternal(Get-Command Get-AgentLocal)
            #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -Verbose:$verbose | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Get-AgentLocal
	    }
    }
}

<#

.Synopsis
   Restarts the Agent Coordinator Service 

.DESCRIPTION
   This script will restart the Agent Coordinator Service


#>

function global:Restart-Coordinator
{
	[CmdletBinding()]
	PARAM(
		[Parameter(Mandatory=$false, ValueFromPipeline=$true)]
		    [STRING[]] $ComputerName=$null
	)

    process
    {
        function Restart-CoordinatorLocal()
        {
            Restart-CoordinatorShared
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
              $Result =  Test-ComputerConnection($computer)
               if($Result)
                {                      
                        $code = Get-CodeInternal(Get-Command Restart-CoordinatorLocal)
		                Invoke-Command -ComputerName $computer -ScriptBlock $code | select -ExcludeProperty RunspaceId
                                       
                } 
            }  
		    #$code = Get-CodeInternal(Get-Command Restart-CoordinatorLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Restart-CoordinatorLocal
	    }
    }
}


<#

.Synopsis
   Agent Installation 

.DESCRIPTION
   This script will install the Agent on local computer or remote computer depending on the value of the "ComputerName" parameter.

.PARAMETER SetupFile
   This describes the path of the installer from where the script should load.

.PARAMETER TemplateFile
   This describes the config.xml file.

.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER SetupFile
   This describes the path of the installer from where the script should load.


.PARAMETER $RemoteShare

.PARAMETER $RemotePath

.PARAMETER RestartIIS
   Depending on the value the IIS Restarts happens.

.PARAMETER RestartWindowsServices
   Depending on the value the Windows service restart happens.

#>

function global:Install-Agent
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
          [ValidateScript({(($_ -ne $null) -and ($_.Count -ge 1) -and ($_.Count -le 2))})]
          [STRING[]] $SetupFile=$null,
        [Parameter(Mandatory=$false, Position=1)]
          [ValidateScript({($_ -eq $null) -or (Test-Path $_ -PathType Leaf)})]
          [STRING] $TemplateFile=$null,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
          [STRING[]] $ComputerName=$null,
        [STRING] $RemoteShare="c$\temp\AppDynamics\Install\",
        [STRING] $RemotePath="c:\temp\AppDynamics\Install\",
        [Switch] $RestartIIS,
        [Switch] $SharePointInstall,
        [STRING[]] $RestartWindowsServices=$null,
        [Hashtable] $Arguments=$null
	)

    process
    {

       #---------Start VISH---------
        
        function Get-WMIService
          {               
                 $ServiceName = Get-Service -Name wmiApSrv              
               
                 if ($ServiceName -ne $null)          
                  {
                     if ($ServiceName.Status -eq "Stopped")
                     {
                           
                           #$ConfirmResult = Ask-Confirm -ServiceName $ServiceName.DisplayName   
                            $confirmation = Read-Host $ServiceName.DisplayName "service is stopped. Do you want to start the service and proceed installation?(Y/N)"                         
                           if($confirmation -eq 'y') #if($ConfirmResult)
                           {
                                Write-Host "Starting Service...."
                                Start-Service $ServiceName.DisplayName
                                Write-Host "Starting " $ServiceName.DisplayName " Service is now started"
                           }else
                           {
                                Write-Host $ServiceName.DisplayName "is stopped.In order to continue the installation, start the service"
                                Throw
                           }
                            #Write-Host "Service Stopped"
                     }else{
                     
                            if ($ServiceName.Status -eq "Running")
                            { 
                                    Write-Host $ServiceName.DisplayName "service is already started"
                            }
                    }
                  }else
                     {
                 
                     Write-Warning $ServiceName.DisplayName "Service DoesNot Exist."
                     Throw
                 
                     } 
            }


             function Get-COMService
              {               
                 $ServiceName = Get-Service -Name COMSysApp               
                                 
               
                 if ($ServiceName -ne $null)          
                  {
                     if ($ServiceName.Status -eq "Stopped")
                     {
                            #$ConfirmResult = Ask-Confirm -ServiceName $ServiceName 
                            $confirmation = Read-Host $ServiceName.DisplayName "service is stopped. Do you want to start the service and proceed installation?(Y/N)"
                            if($confirmation -eq 'y') #if($ConfirmResult)
                            {
                                Write-Host "Starting Service...."  
                                Start-Service $ServiceName
                                Write-Host "Starting " $ServiceName.DisplayName " Service is now started"
                                #Write-Host "Service Stopped"
                             }else
                             {
                                Write-Host $ServiceName.DisplayName "is stopped.In order to continue the installation, start the service"
                                #Break
                                Throw
                             }

                     }else{
                     
                            if ($ServiceName.Status -eq "Running")
                            { 
                                    Write-Host $ServiceName.DisplayName "service is already started"
                            }
                    }
                  }else
                     {
                 
                     Write-Warning $ServiceName.DisplayName "Service DoesNot Exist."
                     Throw
                 
                     } 
            }   
        
            <#   if($ComputerName -ne $null)
                {
                  foreach($computer in $ComputerName)
                   {
                      
                      $Result =  Test-ComputerConnection($computer)
                      if($Result)
                       {
                         if($computer -ne $null)
                         {  
                          $code = Get-CodeInternal(Get-Command Get-WMIService)                          
		                  Invoke-Command -ComputerName $computer -ScriptBlock $code 
                          $code = Get-CodeInternal(Get-Command Get-COMService)                          
		                  Invoke-Command -ComputerName $computer -ScriptBlock $code 
                         }
                   
                       }
               
                   }
                }
                else               
                {
                $code = Get-CodeInternal(Get-Command Get-WMIService) 
                Invoke-Command -ScriptBlock $code 
                $code = Get-CodeInternal(Get-Command Get-COMService) 
		        Invoke-Command -ScriptBlock $code                 
                } #>

       #---------END----------
        function Setup-MsiLocal(
            [string] $Setup64File,
            [string] $Setup32File,
            [string] $TemplateFile,
            [Bool] $RestartIIS,
            [String[]] $RestartWindowsServices,
            [Bool] $SharePointInstall,
            [Hashtable] $Arguments
            )
        {
           
            $setup_file = $Setup32File
	        if(Get-64ArchitectureShared) { $setup_file = $Setup64File }

            if(([string]::IsNullOrEmpty($setup_file) -or (-Not (Test-Path $setup_file -PathType Leaf))))
            {
                Throw "Agent install file $setup_file is not found."
            }

            $version = Get-MsiProductVersionShared $setup_file

            $agent = Get-AgentShared
            if($agent -ne $null)
            {
                $local_version = [Version]$agent.DisplayVersion
                if($version.CompareTo($local_version) -eq 1)
                {
                    Stop-ApplicationShared $RestartIIS $RestartWindowsServices
                    $exitcode = Uninstall-AgentShared

                    if($exitcode -eq 0)
                    {
                        $exitcode = Install-AgentShared $setup_file $TemplateFile $Arguments
                        if($exitcode -eq 0)
                        {
                            Restart-CoordinatorShared
                            Start-ApplicationShared $RestartIIS $RestartWindowsServices

                            $result = @{Result=$true; Message=".NET agent $version successfully upgraded from $local_version."}
                            New-Object PSObject –Property $result

                            RegistryChanges-Shared($SharePointInstall)
                        }
                        else
                        {
                            $result = @{Result=$false; Message=".NET agent $version install failed. Error code: $exitcode"}
                            New-Object PSObject –Property $result
                        }
                    }
                    else
                    {
                        $result = @{Result=$false; Message=".NET agent $local_version uninstall failed. Error code: $exitcode"}
                        New-Object PSObject –Property $result
                    }
                }
                else
                {
                    $result = @{Result=$false; Message="Installed version: $local_version. New version: $version. No upgrade required."}
                    New-Object PSObject –Property $result
                }
            }
            else
            {
                $exitcode = Install-AgentShared $setup_file $TemplateFile $Arguments
                if($exitcode -ne 0)
                {
                    $result = @{Result=$false; Message=".NET agent $version install failed. Error code: $exitcode"}
                    New-Object PSObject –Property $result
                }
                else
                {
                    Restart-CoordinatorShared
                    Restart-ApplicationShared $RestartIIS $RestartWindowsServices

                    $result = @{Result=$true; Message=".NET agent $version successfully installed."}
                    New-Object PSObject –Property $result

                    RegistryChanges-Shared($SharePointInstall)
                }
            }
        }

        function Setup-MsiRemote(
            [STRING[]] $ComputerName,
            [STRING] $Setup64File,
            [STRING] $Setup32File,
            [STRING] $TemplateFile,
            [STRING] $RemoteShare,
            [STRING] $RemotePath,
            [Bool] $RestartIIS,
            [STRING[]] $RestartWindowsServices,
            [bool] $SharePointInstall,
            [Hashtable] $Arguments)
        {
            #Copy files for remote install
            [array] $files = @()
            [string]$remote_setup32 = $null
            [string]$remote_setup64 = $null
            [string]$remote_template = $null
            
            if((-Not [string]::IsNullOrEmpty($Setup64File)) -and (Test-Path -Path $Setup64File -PathType Leaf)) 
            {
                $files += $Setup64File 
                $remote_setup64 = Join-Path -Path $RemotePath -ChildPath (Split-Path $Setup64File -Leaf)
            }

            if((-Not [string]::IsNullOrEmpty($Setup32File)) -and (Test-Path -Path $Setup32File -PathType Leaf))
            {
                $files += $Setup32File 
                $remote_setup32 = Join-Path -Path $RemotePath -ChildPath (Split-Path $Setup32File -Leaf)
            }

            if((-Not [string]::IsNullOrEmpty($TemplateFile)) -and (Test-Path -Path $TemplateFile -PathType Leaf)) 
            {
                $files += $TemplateFile
                $remote_template = Join-Path -Path $RemotePath -ChildPath (Split-Path $TemplateFile -Leaf)
            }

            Copy-FilesToRemoteComputersInternal $files $ComputerName $RemoteShare
            
            #Run the installer
            $code = Get-CodeInternal(Get-Command Setup-MsiLocal)            
	        Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $remote_setup64, $remote_setup32, $remote_template, $RestartIIS, $RestartWindowsServices, $SharePointInstall ,$Arguments | select -ExcludeProperty RunspaceId
        }


        # Parse setup file names into 32 and 64 bit by thecking the names
        $Setup64File = $null
        $Setup32File = $null

        foreach($file in $SetupFile)
        {
            # check if file name ends with '64' or not
            if((-Not [string]::IsNullOrEmpty($file)) -and (Test-Path -Path $file -PathType Leaf))
            {
                $name = [System.IO.Path]::GetFileNameWithoutExtension($file)
                if($name.Contains("64")) { $Setup64File = $file }
                else { $Setup32File = $file }
            }
        }

        # Main logic - validate parameters
        if(-Not ((Test-Path -Path $Setup64File -PathType Leaf) -or (Test-Path -Path $Setup32File -PathType Leaf)))
        {
            Throw "Agent msi files were not found."
        }

        #Test ComputerName value
        if($ComputerName -ne $null)
        {
           foreach($computer in $ComputerName)
           {
             $Result =  Test-ComputerConnection($computer)
             if($Result)
              {
                $code = Get-CodeInternal(Get-Command Get-WMIService)                          
		        Invoke-Command -ComputerName $computer -ScriptBlock $code 
                $code = Get-CodeInternal(Get-Command Get-COMService)                          
		        Invoke-Command -ComputerName $computer -ScriptBlock $code 
                Setup-MsiRemote $computer $Setup64File $Setup32File $TemplateFile $RemoteShare $RemotePath $RestartIIS $RestartWindowsServices $SharePointInstall $Arguments 
              }
           }
         
            #Setup-MsiRemote $ComputerName $Setup64File $Setup32File $TemplateFile $RemoteShare $RemotePath $RestartIIS $RestartWindowsServices $Arguments
        }
        else
        {
            #Setup locally
            $code = Get-CodeInternal(Get-Command Get-WMIService) 
            Invoke-Command -ScriptBlock $code 
            $code = Get-CodeInternal(Get-Command Get-COMService) 
		    Invoke-Command -ScriptBlock $code                 
            Setup-MsiLocal $Setup64File $Setup32File $TemplateFile $RestartIIS $RestartWindowsServices $SharePointInstall $Arguments 
        }
    }
}


<#

.Synopsis
   Agent UnInstall

.DESCRIPTION
   This script will UnInstall the Agent on local computer or remote computer depending on the value 
   of the "ComputerName" parameter.


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Depending on the value the IIS Restarts happens.

.PARAMETER RestartWindowsServices
   Depending on the value the Windows service restart happens.

#>

function global:Uninstall-Agent
{
	[CmdletBinding()]
	PARAM(
		[Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [switch] $RestartIIS,
        [STRING[]] $RestartWindowsServices
	)

    process
    {
	    function Uninstall-AgentLocal([Bool] $RestartIIS, [String[]] $RestartWindowsServices)
	    {
		    $agent=Get-AgentShared
	
	        if($agent -ne $null) 
	        {
                Stop-ApplicationShared $RestartIIS $RestartWindowsServices
                $local_version = [Version]$agent.DisplayVersion
                $exitcode = Uninstall-AgentShared

                if($exitcode -ne 0)
                {
                    $result = @{Result=$false; Message=".NET agent $local_version uninstall failed. Error code: $exitcode"}
                    New-Object PSObject –Property $result
                }
                else
                {
                    Start-ApplicationShared $RestartIIS $RestartWindowsServices

                    $result = @{Result=$true; Message=".NET agent $local_version uninstall completed successfully."}
                    New-Object PSObject –Property $result
                }
	        }
            else
            {
                $result = @{Result=$false; Message=".NET agent is not installed."}
                New-Object PSObject –Property $result
            }

	    }


	    #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
                  $Result =  Test-ComputerConnection($computer)
                  if($Result)
                  {
                   if($computer -ne $null)
                   {
                        $code = Get-CodeInternal(Get-Command Uninstall-AgentLocal)
		                Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $RestartIIS, $RestartWindowsServices | select -ExcludeProperty RunspaceId
                        Write-Output "Successfully uninstalled agent from $computer"
                   }
                  
                  }
            
            } 
		    #$code = Get-CodeInternal(Get-Command Uninstall-AgentLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $RestartIIS, $RestartWindowsServices | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Uninstall-AgentLocal $RestartIIS $RestartWindowsServices
	    }
    }
}


<#

.Synopsis
   Updates Config.xml

.DESCRIPTION
   This script will update the agent configuration file on local computer or remote computer depending on the value of the "ComputerName" parameter.


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER TemplateFile
   This describes the config.xml file.

.PARAMETER RestartIIS
   Depending on the value the IIS Restarts happens.

.PARAMETER RestartWindowsServices
   Depending on the value the Windows service restart happens.

.PARAMETER RemoteShare

.PARAMETER RemotePath


#>

function global:Update-ConfigurationFromTemplate
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
            [STRING] $TemplateFile,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [STRING] $RemoteShare="c$\temp\AppDynamics\Install\",
        [STRING] $RemotePath="c:\temp\AppDynamics\Install\",
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null
	)

    process
    {
        function Update-AgentConfigurationFromTemplateLocal([STRING] $TemplateFile, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices)
        {
            $registry_path = 'HKLM:\Software\AppDynamics\dotNet Agent\'
		    if(Test-Path $registry_path)
            {
                $install = Get-ItemProperty $registry_path
                if($install.InstallationDir -ne $null)
                {
                    $template_path = Resolve-Path $TemplateFile
                    $filename = Join-Path -Path $install.InstallationDir -ChildPath "AppDynamics.Agent.Winston.exe"
                    $arguments = ' -c "' + $template_path + '"'
                    $exitcode = Execute-CommandShared $filename $arguments

                    if($exitcode -ne 0)
                    {
                        $result = @{Result=$false; Message=".NET agent configuration apply failed. Error code: $exitcode"}
                        New-Object PSObject –Property $result
                    }
                    else
                    {
                        Restart-CoordinatorShared
                        Restart-ApplicationShared $RestartIIS $RestartWindowsServices

                        $result = @{Result=$true; Message=".NET agent configuration applied successfully."}
                        New-Object PSObject –Property $result
                    }
                }
            }
            else
            {
                $result = @{Result=$false; Message=".NET agent is not installed."}
                New-Object PSObject –Property $result
            }
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
                $Result =  Test-ComputerConnection($computer)
                if($Result)
                {
                 if($computer -ne $null)
                 {
                    Copy-FilesToRemoteComputersInternal ($TemplateFile) $ComputerName $RemoteShare
                    $remote_template = Join-Path -Path $RemotePath -ChildPath (Split-Path $TemplateFile -Leaf)

                    $code = Get-CodeInternal(Get-Command Update-AgentConfigurationFromTemplateLocal)
		            Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $remote_template, $RestartIIS, $RestartWindowsServices | select -ExcludeProperty RunspaceId
                 }
                }
            }
            #Copy-FilesToRemoteComputersInternal ($TemplateFile) $ComputerName $RemoteShare
            #$remote_template = Join-Path -Path $RemotePath -ChildPath (Split-Path $TemplateFile -Leaf)

            #$code = Get-CodeInternal(Get-Command Update-AgentConfigurationFromTemplateLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $remote_template, $RestartIIS, $RestartWindowsServices | select -ExcludeProperty RunspaceId 
	    }
	    else
	    {
		    Update-AgentConfigurationFromTemplateLocal $TemplateFile $RestartIIS $RestartWindowsServices
	    }
    }
}

<#

.Synopsis
   Gets the .msi version

.DESCRIPTION
   This script will retrives the version of .msi(DotnetAgent Installer).


.PARAMETER SetupFile
   This describes path of the .msi(DotnetAgent Installer).

#>


function global:Get-MsiVersion
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({Test-Path $_ -PathType Leaf})]
            [STRING[]] $SetupFile
	)

    process
    {
        foreach($f in $SetupFile)
        {
            $file = Resolve-Path $f
            $version = Get-MsiProductVersionShared $file
            $version
        }
    }

}


<#

.Synopsis
   Add-Standalone Application Monitoring 

.DESCRIPTION
   This script will add the standalone machine configuration in the config.xml file

.PARAMETER Applications
   This provides the list/names of applications to be configured


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Boolean value to restart IIS or not


.PARAMETER RestartWindowsServices
   Boolean value to RestartWindowsServices  agent co-ordinator service  or not

.PARAMETER Override

#>


function global:Add-StandaloneAppMonitoring
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({$_ -ne $null})]
            [ARRAY] $Applications,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null,
        [SWITCH] $Override = $false
	)

    process
    {
        function Add-ExecutableMonitoringLocal([ARRAY] $Applications, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices, [BOOL] $Override)
        {
            Add-ExecutableMonitoringShared $Applications $Override
            Restart-CoordinatorShared
            Restart-ApplicationShared $RestartIIS $RestartWindowsServices

            $result = @{Result=$true; Message="Standalone was added for monitoring."}
            New-Object PSObject –Property $result
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
                $Result =  Test-ComputerConnection($computer)
                if($Result)
                {
                  $code = Get-CodeInternal(Get-Command Add-ExecutableMonitoringLocal)
		          Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
                }
            }    
            #$code = Get-CodeInternal(Get-Command Add-ExecutableMonitoringLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Add-ExecutableMonitoringLocal $Applications $RestartIIS $RestartWindowsServices $Override
	    }
    }
}


<#

.Synopsis
   Add-Windows Service Monitoring 

.DESCRIPTION
   This script will add the windows service  configuration in the config.xml file

.PARAMETER Applications
   This provides the list/names of applications to be configured


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Boolean value to restart IIS or not


.PARAMETER RestartWindowsServices
   Boolean value to RestartWindowsServices  agent co-ordinator service  or not

.PARAMETER Override

#>



function global:Add-WindowsServiceMonitoring
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({$_ -ne $null})]
            [Array] $Applications,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null,
        [SWITCH] $Override = $false
	)

    process
    {
        function Add-WindowsServiceMonitoringLocal([ARRAY] $Applications, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices, $Override)
        {
            Add-WindowsServiceMonitoringShared $Applications $Override
            Restart-CoordinatorShared
            Restart-ApplicationShared $RestartIIS $RestartWindowsServices

            $result = @{Result=$true; Message="Windows service was added for monitoring."}
            New-Object PSObject –Property $result
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
                $Result =  Test-ComputerConnection($computer)
                if($Result)
                {
                  $code = Get-CodeInternal(Get-Command Add-WindowsServiceMonitoringLocal)
		          Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
                }
            } 
            #$code = Get-CodeInternal(Get-Command Add-WindowsServiceMonitoringLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Add-WindowsServiceMonitoringLocal $Applications $RestartIIS $RestartWindowsServices $Override
	    }
    }
}


<#

.Synopsis
    Add-IISApplicationMonitoring

.DESCRIPTION
   This script will add the  IIS hosted application configuration in the config.xml file

.PARAMETER Applications
   This provides the list/names of applications to be configured


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Boolean value to restart IIS or not


.PARAMETER RestartWindowsServices
   Boolean value to RestartWindowsServices  agent co-ordinator service  or not


.PARAMETER Override

#>



function global:Add-IISApplicationMonitoring
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
        [ValidateScript({$_ -ne $null})]
            [ARRAY] $Applications,
        [Parameter(ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null,
        [SWITCH] $Override = $false
	)

    process
    {
        function Add-IISApplicationLocal([ARRAY] $Applications, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices, [BOOL]$Override)
        {
            Add-IISApplicationMonitoringShared $Applications $Override
            Restart-CoordinatorShared
            Restart-ApplicationShared $RestartIIS $RestartWindowsServices

            $result = @{Result=$true; Message="IIS application was added for monitoring."}
            New-Object PSObject –Property $result
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
                $Result =  Test-ComputerConnection($computer)
                if($Result)
                {
                    $code = Get-CodeInternal(Get-Command Add-IISApplicationLocal)
		            Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
                
                }
            }
            
            #$code = Get-CodeInternal(Get-Command Add-IISApplicationLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $Applications, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Add-IISApplicationLocal $Applications $RestartIIS $RestartWindowsServices $Override
	    }
    }
}

<#

.Synopsis
    Update-ConfigurationFromScript

.DESCRIPTION
   This script will update the config.xml file with the values provided.

.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Boolean value to restart IIS or not


.PARAMETER RestartWindowsServices
   Boolean value to RestartWindowsServices  agent co-ordinator service  or not

.PARAMETER Override

#>

function global:Update-ConfigurationFromScript
{
	[CmdletBinding()]
	PARAM(
        [Parameter(Mandatory=$true, Position=0)]
            [Object] $ScriptBlock,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null,
        [SWITCH] $Override = $false
	)

    process
    {
        function Update-ConfigurationFromScriptLocal([Object] $ScriptBlock, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices, [BOOL]$Override)
        {
            $command = $ScriptBlock
            if($ScriptBlock.GetType() -eq [String])
            {
                $command = [scriptblock]::Create($ScriptBlock)
            }

            $configuration = Invoke-Command -ScriptBlock $command

            if($configuration.Standalone -ne $null)
            {
                Add-ExecutableMonitoringShared $configuration.Standalone $Override
            }

            if($configuration.WindowsService -ne $null)
            {
                Add-WindowsServiceMonitoringShared $configuration.WindowsService $Override
            }

            if($configuration.IIS -ne $null)
            {
                Add-IISApplicationMonitoringShared $configuration.IIS $Override
            }

            Restart-CoordinatorShared
            Restart-ApplicationShared $RestartIIS $RestartWindowsServices

            $result = @{Result=$true; Message="Configuration was successfully applied."}
            New-Object PSObject –Property $result
        }


        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
              $Result =  Test-ComputerConnection($computer)
              if($Result)
               {
                 $command = ([scriptblock]::Create("Get-Command $ScriptBlock")).Invoke()

                $localCommand = Get-Command Update-ConfigurationFromScriptLocal
                $code = Get-CodeInternal $localCommand $command
		        Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $ScriptBlock, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
               
               }
            
            }
            #$command = ([scriptblock]::Create("Get-Command $ScriptBlock")).Invoke()

            #$localCommand = Get-Command Update-ConfigurationFromScriptLocal
            #$code = Get-CodeInternal $localCommand $command
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $ScriptBlock, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Update-ConfigurationFromScriptLocal $ScriptBlock $RestartIIS $RestartWindowsServices $Override
	    }
    }
}


<#

.Synopsis
    Update-Configuration

.DESCRIPTION
   This script will update the config.xml file with the values provided.

.PARAMETER Host
   The value should be the controller host(Name of the computer in which the controller is installed)

.PARAMETER SSL
    Boolean value to enable SSL or not. Default value is false.

.PARAMETER AccountName
    If the controller is on SaaS or installed in multinent mode then you have to enter this value.

.PARAMETER AccessKey
   If the controller is on SaaS or installed in multinent mode then you have to enter this value.

.PARAMETER Applications
   This provides the list/names of applications to be configured


.PARAMETER ComputerName
   This describes the name of the computer to install the agent.

.PARAMETER RestartIIS
   Boolean value to restart IIS or not


.PARAMETER RestartWindowsServices
   Boolean value to RestartWindowsServices  agent co-ordinator service  or not

.PARAMETER Override

#>

function global:Update-Configuration
{
	[CmdletBinding()]
	PARAM(
        [STRING] $HostName = $null,
        [System.UInt16] $Port = 0,
        [SWITCH] $SSL = $false,
        [STRING] $Application = $null,
        [STRING] $AccountName = $null,
        [STRING] $AccessKey = $null,
        [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
        [SWITCH] $RestartIIS,
        [STRING[]] $RestartWindowsServices = $null,
        [SWITCH] $Override = $false
	)

    process
    {
        function Update-ConfigurationLocal([STRING] $HostName, [STRING] $Port, [STRING] $SSL, [STRING] $Application, [STRING] $AccountName, [STRING] $AccessKey, [bool] $RestartIIS, [STRING[]] $RestartWindowsServices)
        {
            Update-AgentConfigurationShared $HostName $Port $SSL $Application $AccountName $AccessKey

            Restart-CoordinatorShared
            Restart-ApplicationShared $RestartIIS $RestartWindowsServices

            $result = @{Result=$true; Message="Configuration was successfully updated."}
            New-Object PSObject –Property $result
        }

        $sslEnabled = $null
        if($MyInvocation.BoundParameters.ContainsKey("SSL"))
        {
            if($SSL)
            {
                $sslEnabled = "true"
            }
            else
            {
                $sslEnabled = "false"
            }
        }

        $portNumber = $null
        if($MyInvocation.BoundParameters.ContainsKey("Port"))
        {
            if($Port -gt 0)
            {
                $portNumber = $Port.ToString()
            }
        }

        #Test ComputerName value
	    if($ComputerName -ne $null)
	    {
            foreach($computer in $ComputerName)
            {
              $Result =  Test-ComputerConnection($computer)
                 if($Result)
                 {
                    $code = Get-CodeInternal(Get-Command Update-ConfigurationLocal)
		            Invoke-Command -ComputerName $computer -ScriptBlock $code -ArgumentList $HostName, $portNumber, $sslEnabled, $Application, $AccountName, $AccessKey, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
                 
                 }
            }
            #$code = Get-CodeInternal(Get-Command Update-ConfigurationLocal)
		    #Invoke-Command -ComputerName $ComputerName -ScriptBlock $code -ArgumentList $HostName, $portNumber, $sslEnabled, $Application, $AccountName, $AccessKey, $RestartIIS, $RestartWindowsServices, $Override | select -ExcludeProperty RunspaceId
	    }
	    else
	    {
		    Update-ConfigurationLocal $HostName $portNumber $sslEnabled $Application $AccountName $AccessKey $RestartIIS $RestartWindowsServices
	    }
    }
}

#-----Start  VISH---------


<#

.Synopsis
   Gets Agentlogs

.DESCRIPTION
    This script will retrives/downloads the DotnetAGent folder

.PARAMETER ComputerName
    This describes the name of the computer to install the agent

.PARAMETER sourcedirectory
    The location where the agent logs are available

.PARAMETER targetdirectory
    The location to copy the agent logs
 

#>


<#function global:Get-AgentLogs
{
    [CmdletBinding()]
	PARAM
       (
		    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
            [STRING] $sourcedirectory=$null,
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [STRING] $targetdirectory=$null      
	    )

    $OSversion =(Get-WmiObject Win32_OperatingSystem).Name

       if ($ComputerName -eq $null)
    {
       
         if(Test-Path $targetdirectory)
           {
                if($OSversion -contains 2003)
                {
                Write-Host $OSversion
                #$sourcedirectory = "$env:AppData\AppDynamics\DotNetAgent\*"
                $sourcedirectory = "C:\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
                Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                Write-Host "Copied files successfully to" $targetdirectory
                }
                else
                {
                Write-Host $OSversion
                #$sourcedirectory = "C:\ProgramData\AppDynamics\DotNetAgent\*" 
                $sourcedirectory = "$env:ProgramData\AppDynamics\DotNetAgent\*" 
                Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                Write-Host "Copied files successfully to" $targetdirectory
                }
        
           }
           else
           {
              New-Item -ItemType directory -Path $targetdirectory
              if(Test-Path $targetdirectory)
              {
                  if($OSversion -contains 2003)
                    {
                    Write-Host $OSversion
                    #$sourcedirectory = "$env:AppData\AppDynamics\DotNetAgent\*"
                    $sourcedirectory = "C:\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
                    Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                    Write-Host "Copied files successfully to" $targetdirectory
                    }
                    else
                    {
                    Write-Host $OSversion
                    #$sourcedirectory = "C:\ProgramData\AppDynamics\DotNetAgent\*" 
                    $sourcedirectory = "$env:ProgramData\AppDynamics\DotNetAgent\*" 
                    Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                    Write-Host "Copied files successfully to" $targetdirectory
                    }
               }else
               {
                Write-Warning $targetdirectory "is not a valid path"
               }
           }

    }
    else
    {

      #$Result =  Test-ComputerConnection($ComputerName)
      foreach($computer in $ComputerName)
       {
          $Result =  Test-ComputerConnection($computer)
          if($Result)
        {      
            Write-Host "Success" $computer
            $targetdirectory = $targetdirectory +"\" + $computer

            if(Test-Path $targetdirectory)
            {
                if($OSversion -contains 2003)
                {
                Write-Host $OSversion            
                $sourcedirectory = "\\$ComputerName\C$\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
                Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                Write-Host "Copied files successfully to" $targetdirectory
                }
                else
                {
                Write-Host $OSversion            
                $sourcedirectory = "\\$ComputerName\C$\ProgramData\AppDynamics\DotNetAgent\*"  
                Write-Host $sourcedirectory
                Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                Write-Host "Copied files successfully to" $targetdirectory
                }
            }
            else
            {
             New-Item -ItemType directory -Path $targetdirectory
              
                if(Test-Path $targetdirectory)
                {
                 if($OSversion -contains 2003)
                    {
                    Write-Host $OSversion            
                    $sourcedirectory = "\\$ComputerName\C$\Documents and Settings\All Users\Application Data\AppDynamics\DotNetAgent\*"
                    Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                    Write-Host "Copied files successfully to" $targetdirectory
                    }
                    else
                    {
                    Write-Host $OSversion            
                    $sourcedirectory = "\\$ComputerName\C$\ProgramData\AppDynamics\DotNetAgent\*"  
                    #$sourcedirectory = "\\$ComputerName\$env:ProgramData\AppDynamics\DotNetAgent\*"  
                    Write-Host $sourcedirectory
                    Copy-Item -Path $sourcedirectory -Destination $targetdirectory -recurse -Force
                    Write-Host "Copied files successfully to" $targetdirectory
                    }
                  }
                  else
                  { 
                    Write-Warning "$targetdirectory is not a valid path"
                  }
            } 
        }

       }
                   
    } 

}#>
function global:Get-AgentLogs
{
    [CmdletBinding()]
	PARAM
       (
		    [Parameter(Mandatory=$false, ValueFromPipeline=$true)]
	    	[STRING[]] $ComputerName=$null,
            [STRING] $sourcedirectory=$null,
            [Parameter(Mandatory=$true, ValueFromPipeline=$true)]
            [STRING] $targetdirectory=$null      
	    )

    $OSversion =(Get-WmiObject Win32_OperatingSystem).Name

    if ($ComputerName -eq $null)
    {
       
        if(Test-Path $targetdirectory)
        {
            Download-AgentLogs $ComputerName $sourcedirectory $targetdirectory
        }
        else
        {
                New-Item -ItemType directory -Path $targetdirectory
                if(Test-Path $targetdirectory)
                {
                    Download-AgentLogs $ComputerName $sourcedirectory $targetdirectory     
                }                   
                else
                {
                Write-Warning $targetdirectory "is not a valid path"
                }
        }

    }
    else
    {

      #$Result =  Test-ComputerConnection($ComputerName)
      foreach($computer in $ComputerName)
       {
          $Result =  Test-ComputerConnection($computer)
          if($Result)
        {      
            Write-Host "Success" $computer

            $targetdirectory = $targetdirectory +"\" + $computer

            if(Test-Path $targetdirectory)
            {
                Download-AgentLogs $ComputerName $sourcedirectory $targetdirectory
            }
            else
            {
                New-Item -ItemType directory -Path $targetdirectory              
                if(Test-Path $targetdirectory)
                    {
                    Download-AgentLogs $ComputerName $sourcedirectory $targetdirectory
                    }
                    else
                    { 
                    Write-Warning "$targetdirectory is not a valid path"
                    }
            } 
         }

       }
                   
     } 

}
#-----END VISH-----------

# Only make CMDLET's available to be used externally but not any of internal or shared functions
Export-ModuleMember -CmdLet ( Get-Command -Module $MyInvocation.MyCommand.ModuleName -CommandType Cmdlet )

Test-IsAdminInternal
Test-PowerShellVersionInternal

Write-Host "AppDynamics .NET agent management PowerShell module is successfully loaded.`r`n
Version: 1.5.4`r`n
Release date: 7 Nov 2017`r`n"