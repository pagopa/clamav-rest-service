
# github environment for deployng to azure
resource "github_repository_environment" "env" {
  environment         = var.github.environment
  repository          = var.github.repository
  prevent_self_review = false
  can_admins_bypass   = true

  deployment_branch_policy {
    protected_branches     = true
    custom_branch_policies = false
  }

  dynamic "reviewers" {
    for_each = var.deployments.review_required ? ["dummy"] : []
    content {
      teams = [
        for t in var.deployments.reviewer_teams :
        data.github_team.reviewers[t].id
      ]
      users = [
        for u in var.deployments.reviewer_users :
        data.github_user.reviewers[u].id
      ]
    }
  }
}

# secrets for allowing github runner to authenticate with federated credentials

resource "github_actions_environment_secret" "arm_tenant_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.env.environment
  secret_name     = "ARM_TENANT_ID"
  plaintext_value = data.azurerm_subscription.current.tenant_id
}

resource "github_actions_environment_secret" "arm_subscription_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.env.environment
  secret_name     = "ARM_SUBSCRIPTION_ID"
  plaintext_value = data.azurerm_subscription.current.subscription_id
}

resource "github_actions_environment_secret" "arm_client_id" {
  repository      = var.github.repository
  environment     = github_repository_environment.env.environment
  secret_name     = "ARM_CLIENT_ID"
  plaintext_value = azurerm_user_assigned_identity.app_cd.client_id
}

# variables for targeting the app service

resource "github_actions_environment_variable" "resource_group_name" {
  repository    = var.github.repository
  environment   = github_repository_environment.env.environment
  variable_name = "RESOURCE_GROUP_NAME"
  value         = var.app_resource_group_name
}

resource "github_actions_environment_variable" "app_name" {
  repository    = var.github.repository
  environment   = github_repository_environment.env.environment
  variable_name = "APP_NAME"
  value         = var.app_name
}
