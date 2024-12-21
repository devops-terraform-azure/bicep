# # Ensure Azure PowerShell module is installed
# if (-not (Get-Module -ListAvailable -Name Az)) {
#     Write-Host "Azure PowerShell module is not installed. Installing now..."
#     Install-Module -Name Az -AllowClobber -Force -Scope CurrentUser
# }

# # Import the Azure module
# Import-Module Az

# # Authenticate to Azure (login to Azure account)
# Connect-AzAccount

# # Define parameters
# $resourceGroupName = 'myresourcegroup'  # Name of your Azure resource group
# $appServiceName = 'myAppService-bicep001'        # Name of your Azure App Service
# $controllerHostName = 'yourControllerHost'    # AppDynamics controller hostname
# $controllerPort = '443'                       # AppDynamics controller port (usually 443)
# $sslEnabled = 'True'                          # SSL enabled for the controller (True/False)
# $accountName = 'yourAccountName'              # AppDynamics account name
# $accountAccessKey = 'yourAccountAccessKey'    # AppDynamics account access key
# $applicationName = 'yourApplicationName'      # AppDynamics application name

# # Get the existing App Service configuration settings
# $appServiceConfig = Get-AzWebAppConfig -ResourceGroupName $resourceGroupName -Name $appServiceName

# # Define the updated app settings for AppDynamics
# $updatedAppSettings = @{
#     'appdynamics.controller.hostName'           = $controllerHostName
#     'appdynamics.controller.port'               = $controllerPort
#     'appdynamics.controller.ssl.enabled'        = $sslEnabled
#     'appdynamics.agent.accountName'             = $accountName
#     'appdynamics.agent.accountAccessKey'        = $accountAccessKey
#     'appdynamics.agent.applicationName'         = $applicationName
# }

# # Update the App Service app settings with new values
# foreach ($key in $updatedAppSettings.Keys) {
#     $value = $updatedAppSettings[$key]
#     Set-AzWebAppConfig -ResourceGroupName $resourceGroupName -Name $appServiceName -AppSettings @{$key = $value}
# }

# Write-Host "AppDynamics Controller Configuration updated successfully!"

# Ensure Azure PowerShell module is installed
if (-not (Get-Module -ListAvailable -Name Az)) {
    Write-Host "Azure PowerShell module is not installed. Installing now..."
    Install-Module -Name Az -AllowClobber -Force -Scope CurrentUser
}

# Import the Azure module
Import-Module Az

# Authenticate to Azure (login to Azure account)
Connect-AzAccount

# Define parameters
$resourceGroupName = 'myresourcegroup'  # Name of your Azure resource group
$appServiceName = 'myAppService-bicep001'        # Name of your Azure App Service
$controllerHostName = 'yourControllerHost'    # AppDynamics controller hostname
$controllerPort = '443'                       # AppDynamics controller port (usually 443)
$sslEnabled = 'True'                          # SSL enabled for the controller (True/False)
$accountName = 'yourAccountName'              # AppDynamics account name
$accountAccessKey = 'yourAccountAccessKey'    # AppDynamics account access key
$applicationName = 'yourApplicationName'      # AppDynamics application name

# Get the existing App Service app settings
$appService = Get-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceName

# Define the updated app settings for AppDynamics
$updatedAppSettings = @{
    'appdynamics.controller.hostName'           = $controllerHostName
    'appdynamics.controller.port'               = $controllerPort
    'appdynamics.controller.ssl.enabled'        = $sslEnabled
    'appdynamics.agent.accountName'             = $accountName
    'appdynamics.agent.accountAccessKey'        = $accountAccessKey
    'appdynamics.agent.applicationName'         = $applicationName
}

# Update the App Service app settings with new values
$existingAppSettings = $appService.SiteConfig.AppSettings
foreach ($key in $updatedAppSettings.Keys) {
    # Remove the existing setting if it exists
    if ($existingAppSettings[$key]) {
        $existingAppSettings.Remove($key)
    }
    # Add or update the app setting
    $existingAppSettings.Add($key, $updatedAppSettings[$key])
}

# Set the new app settings
Set-AzWebApp -ResourceGroupName $resourceGroupName -Name $appServiceName -AppSettings $existingAppSettings

Write-Host "AppDynamics Controller Configuration updated successfully!"
