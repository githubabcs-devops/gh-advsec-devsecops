# ASP.NET Web App Blueprint

## Overview

A containerized ASP.NET web application deployed to Azure App Service using Azure Container Registry (ACR) with managed identity authentication.

## Architecture Components

| Component | Azure Service | Purpose |
| --- | --- | --- |
| Web Application | App Service (Linux) | Hosts the containerized ASP.NET application |
| Container Registry | Azure Container Registry | Stores Docker container images |
| Identity | System-Assigned Managed Identity | Secure authentication to ACR without credentials |

## Data Flows

1. Container images are pushed to Azure Container Registry
2. App Service pulls container images from ACR using managed identity (AcrPull role)
3. Users access the web application via HTTPS

## Deployment

### Prerequisites

- Azure CLI installed and authenticated
- Azure subscription with appropriate permissions
- PowerShell (for deployment script)

### Parameters

| Parameter | Description | Default |
| --- | --- | --- |
| `acrName` | Name of the Azure Container Registry | Required |
| `acrSku` | SKU of the Container Registry | `Basic` |
| `appServicePlanName` | Name of the App Service Plan | Required |
| `webAppName` | Name of the Web App | Required |
| `location` | Azure region for resources | Required |
| `containerImage` | Container image to deploy | Required |
| `resourceGroupName` | Name of the Resource Group | `rg-webapp01-dev` |

### Deploy

```powershell
cd bicep
./deploy.ps1
```

Or deploy directly with Azure CLI:

```bash
az deployment sub create \
  --location <location> \
  --template-file ./bicep/main.bicep \
  --parameters ./bicep/main.parameters.json
```

## Security Considerations

- Admin user disabled on ACR; managed identity used instead
- System-assigned managed identity eliminates credential storage
- AcrPull role assignment follows least-privilege principle
- App Service runs on Linux with container isolation

## Outputs

| Output | Description |
| --- | --- |
| `webAppName` | Name of the deployed Web App |
| `webAppUrl` | HTTPS URL of the Web App |
| `acrLoginServer` | Login server URL for the Container Registry |
| `webAppPrincipalId` | Principal ID of the Web App's managed identity |
