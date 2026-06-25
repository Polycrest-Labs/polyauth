@description('Resource group location')
param location string = resourceGroup().location

@description('Token used to make resource names unique')
param resourceToken string

param firebaseProjectId string
param firebaseApiKey string
param firebaseAuthDomain string
param firebaseAppId string

@secure()
param firebaseServiceAccountB64 string
@secure()
param signingCertificateB64 string
@secure()
param encryptionCertificateB64 string

var webName = 'web-${resourceToken}'
var mcpUiName = 'mcpui-${resourceToken}'
var webUrl = 'https://${webName}.azurewebsites.net'
var mcpUiUrl = 'https://${mcpUiName}.azurewebsites.net'
var openIddictDatabaseName = 'polyauth-openiddict'
var cosmosSqlDatabaseName = 'polyauth-sample'

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: 'log-${resourceToken}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: 'appi-${resourceToken}'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

// Cosmos DB for MongoDB (RU serverless) — backs the OpenIddict store.
resource cosmosMongo 'Microsoft.DocumentDB/databaseAccounts@2024-11-15' = {
  name: 'mongo-${resourceToken}'
  location: location
  kind: 'MongoDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    apiProperties: { serverVersion: '7.0' }
    capabilities: [ { name: 'EnableServerless' } ]
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    locations: [ { locationName: location, failoverPriority: 0, isZoneRedundant: false } ]
  }
}

resource mongoDatabase 'Microsoft.DocumentDB/databaseAccounts/mongodbDatabases@2024-11-15' = {
  parent: cosmosMongo
  name: openIddictDatabaseName
  properties: {
    resource: { id: openIddictDatabaseName }
  }
}

// Cosmos DB for NoSQL (serverless) — backs the sample "items" API.
resource cosmosSql 'Microsoft.DocumentDB/databaseAccounts@2024-11-15' = {
  name: 'sql-${resourceToken}'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    capabilities: [ { name: 'EnableServerless' } ]
    consistencyPolicy: { defaultConsistencyLevel: 'Session' }
    locations: [ { locationName: location, failoverPriority: 0, isZoneRedundant: false } ]
  }
}

resource plan 'Microsoft.Web/serverfarms@2024-04-01' = {
  name: 'plan-${resourceToken}'
  location: location
  sku: { name: 'B1' }
  kind: 'linux'
  properties: { reserved: true }
}

resource web 'Microsoft.Web/sites@2024-04-01' = {
  name: webName
  location: location
  tags: { 'azd-service-name': 'web' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|10.0'
      alwaysOn: true
      ftpsState: 'Disabled'
      appSettings: [
        { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
        { name: 'PolyAuth__Firebase__Enabled', value: 'true' }
        { name: 'PolyAuth__Firebase__ProjectId', value: firebaseProjectId }
        { name: 'PolyAuth__Firebase__ServiceAccountJson', value: base64ToString(firebaseServiceAccountB64) }
        { name: 'PolyAuth__OAuth__Enabled', value: 'true' }
        { name: 'PolyAuth__OAuth__Issuer', value: webUrl }
        { name: 'PolyAuth__OAuth__Store__ConnectionString', value: cosmosMongo.listConnectionStrings().connectionStrings[0].connectionString }
        { name: 'PolyAuth__OAuth__Store__DatabaseName', value: openIddictDatabaseName }
        { name: 'PolyAuth__OAuth__SigningCertificate__Base64', value: signingCertificateB64 }
        { name: 'PolyAuth__OAuth__EncryptionCertificate__Base64', value: encryptionCertificateB64 }
        { name: 'PolyAuth__Mcp__Enabled', value: 'true' }
        { name: 'PolyAuth__Mcp__McpBaseUrl', value: webUrl }
        { name: 'PolyAuth__Mcp__WidgetHostBaseUrl', value: mcpUiUrl }
        { name: 'UiClient__firebase__apiKey', value: firebaseApiKey }
        { name: 'UiClient__firebase__authDomain', value: firebaseAuthDomain }
        { name: 'UiClient__firebase__projectId', value: firebaseProjectId }
        { name: 'UiClient__firebase__appId', value: firebaseAppId }
        { name: 'CosmosDb__ConnectionString', value: cosmosSql.listConnectionStrings().connectionStrings[0].connectionString }
        { name: 'CosmosDb__DatabaseId', value: cosmosSqlDatabaseName }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: appInsights.properties.ConnectionString }
      ]
    }
  }
}

resource mcpUi 'Microsoft.Web/sites@2024-04-01' = {
  name: mcpUiName
  location: location
  tags: { 'azd-service-name': 'mcp-ui' }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOTNETCORE|10.0'
      alwaysOn: true
      ftpsState: 'Disabled'
      appSettings: [
        { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
      ]
    }
  }
}

output WEB_URI string = webUrl
output MCP_UI_URI string = mcpUiUrl
output WEB_NAME string = webName
output MCP_UI_NAME string = mcpUiName
