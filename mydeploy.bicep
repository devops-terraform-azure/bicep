param location string = resourceGroup().location
param appServicePlanName string = 'myAppServicebicep001Plan'
param appServiceName string = 'myAppService-bicep001'
param appServiceSku string = 'P1v2'

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
  }
}

resource symbolicname 'Microsoft.Web/sites/siteextensions@2024-04-01' = {
  parent: appService
  name: 'AppDynamics.WindowsAzure.SiteExtension.4.5.Release'
}
