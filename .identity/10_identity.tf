# managed identity used for cd
resource "azurerm_user_assigned_identity" "app_cd" {
  name                = "${local.project}-itops-clamav-app-cd-id"
  resource_group_name = var.identity_resource_group_name
  location            = var.location
  tags                = var.tags
}

# at least one role on a resource group is required for federated login with managed identity
data "azurerm_resource_group" "default_assignment_rg" {
  name = "default-roleassignment-rg"
}
resource "azurerm_role_assignment" "cd_default_role_assignment" {
  scope                = data.azurerm_resource_group.default_assignment_rg.id
  role_definition_name = "Reader"
  principal_id         = azurerm_user_assigned_identity.app_cd.principal_id
}


# make the cd identity contributor of the app service
resource "azurerm_role_assignment" "app_cd_app_contributor" {
  scope                = data.azurerm_linux_web_app.app.id
  role_definition_name = "Contributor"
  principal_id         = azurerm_user_assigned_identity.app_cd.principal_id
}

# add the federated credentials for allowing github to login as the managed identity in target env
resource "azurerm_federated_identity_credential" "environment" {
  parent_id           = azurerm_user_assigned_identity.app_cd.id
  resource_group_name = var.identity_resource_group_name
  name                = "github-federated-env"
  audience            = ["api://AzureADTokenExchange"]
  issuer              = "https://token.actions.githubusercontent.com"
  subject             = "repo:${var.github.org}/${var.github.repository}:environment:${var.github.environment}"
}
