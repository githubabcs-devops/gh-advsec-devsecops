<#
.SYNOPSIS
    Deploys Azure infrastructure using Bicep templates.

.DESCRIPTION
    This script deploys the Azure infrastructure defined in main.bicep
    using the parameters from main.parameters.json.

.PARAMETER ParameterFile
    Path to the parameters file. Defaults to main.parameters.json.

.PARAMETER Location
    Azure region for deployment. Defaults to canadacentral.

.PARAMETER DeploymentName
    Name of the deployment. Defaults to a timestamped name.

.PARAMETER WhatIf
    Performs a what-if operation without actually deploying.

.EXAMPLE
    .\deploy.ps1

.EXAMPLE
    .\deploy.ps1 -Location "eastus" -WhatIf
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$ParameterFile = "main.parameters.json",

    [Parameter(Mandatory = $false)]
    [string]$Location = "canadacentral",

    [Parameter(Mandatory = $false)]
    [string]$DeploymentName = "deploy-$(Get-Date -Format 'yyyyMMdd-HHmmss')",

    [Parameter(Mandatory = $false)]
    [switch]$WhatIf
)

$ErrorActionPreference = "Stop"

# Get the script directory
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path

# Resolve paths
$BicepFile = Join-Path $ScriptDir "main.bicep"
$ParameterFilePath = Join-Path $ScriptDir $ParameterFile

# Validate files exist
if (-not (Test-Path $BicepFile)) {
    Write-Error "Bicep file not found: $BicepFile"
    exit 1
}

if (-not (Test-Path $ParameterFilePath)) {
    Write-Error "Parameter file not found: $ParameterFilePath"
    exit 1
}

# Check if Azure CLI is installed
if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI is not installed. Please install it from https://docs.microsoft.com/cli/azure/install-azure-cli"
    exit 1
}

# Check if logged in to Azure
$account = az account show 2>$null | ConvertFrom-Json
if (-not $account) {
    Write-Host "Not logged in to Azure. Please log in..." -ForegroundColor Yellow
    az login
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed to log in to Azure"
        exit 1
    }
}

Write-Host "=== Azure Infrastructure Deployment ===" -ForegroundColor Cyan
Write-Host "Subscription: $($account.name)" -ForegroundColor Green
Write-Host "Bicep File: $BicepFile" -ForegroundColor Green
Write-Host "Parameters: $ParameterFilePath" -ForegroundColor Green
Write-Host "Location: $Location" -ForegroundColor Green
Write-Host "Deployment: $DeploymentName" -ForegroundColor Green
Write-Host ""

if ($WhatIf) {
    Write-Host "Running What-If analysis..." -ForegroundColor Yellow
    az deployment sub what-if `
        --name $DeploymentName `
        --location $Location `
        --template-file $BicepFile `
        --parameters @$ParameterFilePath
}
else {
    Write-Host "Starting deployment..." -ForegroundColor Yellow
    az deployment sub create `
        --name $DeploymentName `
        --location $Location `
        --template-file $BicepFile `
        --parameters @$ParameterFilePath

    if ($LASTEXITCODE -eq 0) {
        Write-Host ""
        Write-Host "Deployment completed successfully!" -ForegroundColor Green
        
        # Show deployment outputs
        Write-Host ""
        Write-Host "Deployment outputs:" -ForegroundColor Cyan
        $outputs = az deployment sub show `
            --name $DeploymentName `
            --query "properties.outputs" `
            --output json | ConvertFrom-Json
        
        $outputs | ConvertTo-Json | Write-Host
        
        # Configure ACR managed identity authentication
        if ($outputs.webAppName) {
            $webAppName = $outputs.webAppName.value
            $resourceGroupName = (az webapp show --name $webAppName --query resourceGroup -o tsv)
            
            Write-Host ""
            Write-Host "Configuring ACR managed identity authentication..." -ForegroundColor Yellow
            
            # Ensure acrUseManagedIdentityCreds is set (should be set by Bicep, but double-check)
            Write-Host "Verifying ACR managed identity configuration..." -ForegroundColor Cyan
            $config = az webapp config show --name $webAppName --resource-group $resourceGroupName --query "acrUseManagedIdentityCreds" -o tsv
            
            if ($config -ne "true") {
                Write-Host "Setting acrUseManagedIdentityCreds=true..." -ForegroundColor Cyan
                az resource update `
                    --ids "/subscriptions/$($account.id)/resourceGroups/$resourceGroupName/providers/Microsoft.Web/sites/$webAppName/config/web" `
                    --set properties.acrUseManagedIdentityCreds=true
            } else {
                Write-Host "ACR managed identity already configured" -ForegroundColor Green
            }
            
            # Restart the web app to apply all changes
            Write-Host "Restarting web app to apply configuration..." -ForegroundColor Cyan
            az webapp restart --name $webAppName --resource-group $resourceGroupName
            
            if ($LASTEXITCODE -eq 0) {
                Write-Host "Web app restarted successfully!" -ForegroundColor Green
                Write-Host ""
                Write-Host "=== Configuration Summary ===" -ForegroundColor Cyan
                Write-Host "✓ System-assigned managed identity enabled" -ForegroundColor Green
                Write-Host "✓ AcrPull role assigned to managed identity" -ForegroundColor Green
                Write-Host "✓ ACR authentication configured to use managed identity" -ForegroundColor Green
                Write-Host "✓ Web app restarted" -ForegroundColor Green
                Write-Host ""
                if ($outputs.webAppUrl) {
                    Write-Host "Web App URL: $($outputs.webAppUrl.value)" -ForegroundColor Green
                }
            } else {
                Write-Warning "Failed to restart web app. You may need to restart it manually."
            }
        }
    }
    else {
        Write-Error "Deployment failed with exit code: $LASTEXITCODE"
        exit $LASTEXITCODE
    }
}
