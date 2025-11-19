
# the app service to deploy
data "azurerm_linux_web_app" "app" {
  name                = var.app_name
  resource_group_name = var.app_resource_group_name
}

# github users for getting graphql ids
data "github_user" "reviewers" {
  for_each = toset(var.deployments.reviewer_users)

  username = each.key
}

# github teams for getting graphql ids
data "github_team" "reviewers" {
  for_each = toset(var.deployments.reviewer_teams)

  slug = each.key
}
