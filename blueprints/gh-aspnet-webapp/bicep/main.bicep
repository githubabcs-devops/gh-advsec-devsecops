// Bicep file to deploy a containerized web app to Azure

@description('The name of the Azure Container Registry')
param acrName string

@description('The SKU of the Azure Container Registry')
param acrSku string = 'Basic'

@description('The name of the App Service Plan')
param appServicePlanName string

@description('The name of the Web App')
param webAppName string

@description('The location for all resources')
param location string

@description('The container image name without registry prefix (e.g., webapp01:latest)')
param containerImageName string = 'webapp01:latest'

@description('The name of the Resource Group')
param resourceGroupName string = 'rg-webapp01-dev'

// Create the resource group at the subscription level
targetScope = 'subscription'

resource resourceGroup 'Microsoft.Resources/resourceGroups@2021-04-01' = {
  name: resourceGroupName
  location: location
}

// Generate unique suffix based on resource group ID for customer-specific uniqueness
var uniqueSuffix = uniqueString(resourceGroup.id)

// Deploy resources within the resource group
module resourcesInRG './resources.bicep' = {
  name: 'deployResourcesInRG'
  scope: resourceGroup
  params: {
    acrName: '${acrName}${uniqueSuffix}'
    acrSku: acrSku
    appServicePlanName: '${appServicePlanName}-${uniqueSuffix}'
    webAppName: '${webAppName}-${uniqueSuffix}'
    location: location
    containerImageName: containerImageName
  }
}

// Expose outputs from the module for use in CI/CD pipelines
output webAppName string = resourcesInRG.outputs.webAppName
output webAppUrl string = resourcesInRG.outputs.webAppUrl
output acrLoginServer string = resourcesInRG.outputs.acrLoginServer
output webAppPrincipalId string = resourcesInRG.outputs.webAppPrincipalId
