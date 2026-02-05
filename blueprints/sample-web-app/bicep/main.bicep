@description('The Azure region for resource deployment.')
param location string = resourceGroup().location

@description('Environment name used for resource naming.')
@allowed(['dev', 'staging', 'prod'])
param environmentName string = 'dev'

@description('Base name for all resources.')
param baseName string = 'samplewebapp'

/* ========================================================================== */
/* Variables                                                                   */
/* ========================================================================== */

var resourceSuffix = '${baseName}-${environmentName}'
var keyVaultName = 'kv-${resourceSuffix}'
var appServicePlanName = 'asp-${resourceSuffix}'
var appServiceName = 'app-${resourceSuffix}'
var sqlServerName = 'sql-${resourceSuffix}'
var sqlDatabaseName = 'sqldb-${resourceSuffix}'
var appInsightsName = 'ai-${resourceSuffix}'
var logAnalyticsName = 'log-${resourceSuffix}'

/* ========================================================================== */
/* Log Analytics Workspace                                                     */
/* ========================================================================== */

@description('Log Analytics workspace for monitoring.')
resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: logAnalyticsName
  location: location
  properties: {
    sku: {
      name: 'PerGB2018'
    }
    retentionInDays: 30
  }
}

/* ========================================================================== */
/* Application Insights                                                        */
/* ========================================================================== */

@description('Application Insights for telemetry.')
resource appInsights 'Microsoft.Insights/components@2020-02-02' = {
  name: appInsightsName
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logAnalytics.id
  }
}

/* ========================================================================== */
/* Key Vault                                                                   */
/* ========================================================================== */

@description('Key Vault for secrets management.')
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: keyVaultName
  location: location
  properties: {
    sku: {
      family: 'A'
      name: 'standard'
    }
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    enablePurgeProtection: true
    networkAcls: {
      defaultAction: 'Deny'
      bypass: 'AzureServices'
    }
  }
}

/* ========================================================================== */
/* App Service Plan                                                            */
/* ========================================================================== */

@description('App Service Plan for hosting.')
resource appServicePlan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: appServicePlanName
  location: location
  sku: {
    name: 'P1v3'
    tier: 'PremiumV3'
  }
  properties: {
    reserved: false
  }
}

/* ========================================================================== */
/* App Service                                                                 */
/* ========================================================================== */

@description('App Service for web application.')
resource appService 'Microsoft.Web/sites@2023-12-01' = {
  name: appServiceName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: appServicePlan.id
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      ftpsState: 'Disabled'
      alwaysOn: true
      appSettings: [
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: appInsights.properties.InstrumentationKey
        }
        {
          name: 'APPLICATIONINSIGHTS_CONNECTION_STRING'
          value: appInsights.properties.ConnectionString
        }
        {
          name: 'KeyVaultUri'
          value: keyVault.properties.vaultUri
        }
      ]
    }
  }
}

/* ========================================================================== */
/* SQL Server                                                                  */
/* ========================================================================== */

@description('SQL Server for database hosting.')
resource sqlServer 'Microsoft.Sql/servers@2023-08-01-preview' = {
  name: sqlServerName
  location: location
  properties: {
    administratorLogin: 'sqladmin'
    minimalTlsVersion: '1.2'
    publicNetworkAccess: 'Disabled'
  }
}

/* ========================================================================== */
/* SQL Database                                                                */
/* ========================================================================== */

@description('SQL Database for application data.')
resource sqlDatabase 'Microsoft.Sql/servers/databases@2023-08-01-preview' = {
  parent: sqlServer
  name: sqlDatabaseName
  location: location
  sku: {
    name: 'S1'
    tier: 'Standard'
  }
  properties: {
    collation: 'SQL_Latin1_General_CP1_CI_AS'
  }
}

/* ========================================================================== */
/* Key Vault Access for App Service                                            */
/* ========================================================================== */

@description('Key Vault Secrets User role assignment for App Service.')
resource keyVaultRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(keyVault.id, appService.id, '4633458b-17de-408a-b874-0445c86b69e6')
  scope: keyVault
  properties: {
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
    principalId: appService.identity.principalId
    principalType: 'ServicePrincipal'
  }
}

/* ========================================================================== */
/* Outputs                                                                     */
/* ========================================================================== */

@description('The App Service default hostname.')
output appServiceHostname string = appService.properties.defaultHostName

@description('The Key Vault URI.')
output keyVaultUri string = keyVault.properties.vaultUri

@description('The SQL Server FQDN.')
output sqlServerFqdn string = sqlServer.properties.fullyQualifiedDomainName
