param sites_myAppService_bicep001_name string = 'myAppService-bicep001'
param serverfarms_myAppServicebicep001Plan_externalid string = '/subscriptions/a9c1f0e0-6971-483e-97d9-f1f6289373e1/resourceGroups/myResourceGroup/providers/Microsoft.Web/serverfarms/myAppServicebicep001Plan'

resource sites_myAppService_bicep001_name_resource 'Microsoft.Web/sites@2023-12-01' = {
  name: sites_myAppService_bicep001_name
  location: 'East US 2'
  kind: 'app'
  properties: {
    enabled: true
    hostNameSslStates: [
      {
        name: 'myappservice-bicep001.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Standard'
      }
      {
        name: 'myappservice-bicep001.scm.azurewebsites.net'
        sslState: 'Disabled'
        hostType: 'Repository'
      }
    ]
    serverFarmId: serverfarms_myAppServicebicep001Plan_externalid
    reserved: false
    isXenon: false
    hyperV: false
    dnsConfiguration: {}
    vnetRouteAllEnabled: false
    vnetImagePullEnabled: false
    vnetContentShareEnabled: false
    siteConfig: {
      numberOfWorkers: 1
      acrUseManagedIdentityCreds: false
      alwaysOn: false
      http20Enabled: false
      functionAppScaleLimit: 0
      minimumElasticInstanceCount: 0
    }
    scmSiteAlsoStopped: false
    clientAffinityEnabled: true
    clientCertEnabled: false
    clientCertMode: 'Required'
    hostNamesDisabled: false
    vnetBackupRestoreEnabled: false
    customDomainVerificationId: 'C3CB8EEC26669E34EC35385D937F2A4A28D62CCDAC91B6D47C761043D0CBF96B'
    containerSize: 0
    dailyMemoryTimeQuota: 0
    httpsOnly: false
    redundancyMode: 'None'
    storageAccountRequired: false
    keyVaultReferenceIdentity: 'SystemAssigned'
  }
}

resource sites_myAppService_bicep001_name_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: sites_myAppService_bicep001_name_resource
  name: 'ftp'
  location: 'East US 2'
  properties: {
    allow: true
  }
}

resource sites_myAppService_bicep001_name_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2023-12-01' = {
  parent: sites_myAppService_bicep001_name_resource
  name: 'scm'
  location: 'East US 2'
  properties: {
    allow: true
  }
}

resource sites_myAppService_bicep001_name_web 'Microsoft.Web/sites/config@2023-12-01' = {
  parent: sites_myAppService_bicep001_name_resource
  name: 'web'
  location: 'East US 2'
  properties: {
    numberOfWorkers: 1
    defaultDocuments: [
      'Default.htm'
      'Default.html'
      'Default.asp'
      'index.htm'
      'index.html'
      'iisstart.htm'
      'default.aspx'
      'index.php'
      'hostingstart.html'
    ]
    netFrameworkVersion: 'v4.0'
    phpVersion: '5.6'
    requestTracingEnabled: false
    remoteDebuggingEnabled: false
    httpLoggingEnabled: false
    acrUseManagedIdentityCreds: false
    logsDirectorySizeLimit: 35
    detailedErrorLoggingEnabled: false
    publishingUsername: '$myAppService-bicep001'
    scmType: 'None'
    use32BitWorkerProcess: true
    webSocketsEnabled: false
    alwaysOn: false
    managedPipelineMode: 'Integrated'
    virtualApplications: [
      {
        virtualPath: '/'
        physicalPath: 'site\\wwwroot'
        preloadEnabled: false
      }
    ]
    loadBalancing: 'LeastRequests'
    experiments: {
      rampUpRules: []
    }
    autoHealEnabled: false
    vnetRouteAllEnabled: false
    vnetPrivatePortsCount: 0
    localMySqlEnabled: false
    ipSecurityRestrictions: [
      {
        ipAddress: 'Any'
        action: 'Allow'
        priority: 2147483647
        name: 'Allow all'
        description: 'Allow all access'
      }
    ]
    scmIpSecurityRestrictions: [
      {
        ipAddress: 'Any'
        action: 'Allow'
        priority: 2147483647
        name: 'Allow all'
        description: 'Allow all access'
      }
    ]
    scmIpSecurityRestrictionsUseMain: false
    http20Enabled: false
    minTlsVersion: '1.2'
    scmMinTlsVersion: '1.2'
    ftpsState: 'FtpsOnly'
    preWarmedInstanceCount: 0
    elasticWebAppScaleLimit: 0
    functionsRuntimeScaleMonitoringEnabled: false
    minimumElasticInstanceCount: 0
    azureStorageAccounts: {}
  }
}

resource sites_myAppService_bicep001_name_sites_myAppService_bicep001_name_azurewebsites_net 'Microsoft.Web/sites/hostNameBindings@2023-12-01' = {
  parent: sites_myAppService_bicep001_name_resource
  name: '${sites_myAppService_bicep001_name}.azurewebsites.net'
  location: 'East US 2'
  properties: {
    siteName: 'myAppService-bicep001'
    hostNameType: 'Verified'
  }
}

resource sites_myAppService_bicep001_name_AppDynamics_WindowsAzure_SiteExtension_4_5_Release 'Microsoft.Web/sites/siteextensions@2023-12-01' = {
  parent: sites_myAppService_bicep001_name_resource
  name: 'AppDynamics.WindowsAzure.SiteExtension.4.5.Release'
  location: 'East US 2'
}
