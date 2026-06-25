targetScope = 'subscription'

@minLength(1)
@description('Name of the azd environment, used to derive resource names')
param environmentName string

@minLength(1)
@description('Primary location for all resources')
param location string

param firebaseProjectId string = ''
param firebaseApiKey string = ''
param firebaseAuthDomain string = ''
param firebaseAppId string = ''

@secure()
param firebaseServiceAccountB64 string = ''
@secure()
param signingCertificateB64 string = ''
@secure()
param encryptionCertificateB64 string = ''

var resourceToken = toLower(uniqueString(subscription().id, environmentName, location))

resource rg 'Microsoft.Resources/resourceGroups@2024-03-01' = {
  name: 'rg-${environmentName}'
  location: location
  tags: { 'azd-env-name': environmentName }
}

module resources 'resources.bicep' = {
  name: 'resources'
  scope: rg
  params: {
    location: location
    resourceToken: resourceToken
    firebaseProjectId: firebaseProjectId
    firebaseApiKey: firebaseApiKey
    firebaseAuthDomain: firebaseAuthDomain
    firebaseAppId: firebaseAppId
    firebaseServiceAccountB64: firebaseServiceAccountB64
    signingCertificateB64: signingCertificateB64
    encryptionCertificateB64: encryptionCertificateB64
  }
}

output WEB_URI string = resources.outputs.WEB_URI
output MCP_UI_URI string = resources.outputs.MCP_UI_URI
output WEB_NAME string = resources.outputs.WEB_NAME
output MCP_UI_NAME string = resources.outputs.MCP_UI_NAME
