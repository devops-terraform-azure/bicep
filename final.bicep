param location string = resourceGroup().location
param appServicePlanName string = 'myAppServicebicep001Plan'
param appServiceName string = 'myAppService-bicep001'
param appServiceSku string = 'P1v2'
param enableAPM string = 'Yes'

var controllerHostName = enableAPM == 'Yes' ? 'myController' : ''
var controllerPort = enableAPM == 'Yes' ? '443' : ''
var sslEnabled = enableAPM == 'Yes' ? 'True' : ''
var accountName = enableAPM == 'Yes' ? 'myCompany' : ''
var accountAccessKey = enableAPM == 'Yes' ? 'myKey' : ''

resource appServicePlan 'Microsoft.Web/serverfarms@2021-02-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: appServiceSku
    tier: 'PremiumV2'
    size: 'P1v2'
    capacity: 1
  }
}

resource appService 'Microsoft.Web/sites@2021-02-01' = {
  name: appServiceName
  location: location
  properties: {
    serverFarmId: appServicePlan.id
    siteConfig: {
      nodeVersion: '20-lts'
    }
  }
}

resource appSettings 'Microsoft.Web/sites/config@2021-02-01' = {
  parent: appService
  name: 'appsettings'
  properties: {
    // Required AppDynamics settings
    'appdynamics.controller.hostName': controllerHostName
    'appdynamics.controller.port': controllerPort
    'appdynamics.controller.ssl.enabled': sslEnabled
    'appdynamics.agent.accountName': accountName 
    'appdynamics.agent.accountAccessKey': accountAccessKey
    // Optional but recommended settings
    'appdynamics.controller.applicationName': appServiceName
    'appdynamics.agent.tierName': appServiceName
    'appdynamics.agent.nodeName': '${appServiceName}-${resourceGroup().name}'
  }
}

resource appDynamicsExtension 'Microsoft.Web/sites/siteextensions@2024-04-01' = {
  parent: appService
  name: 'AppDynamics.WindowsAzure.SiteExtension.4.5.Release'
  dependsOn: [
    appSettings
  ]
}
