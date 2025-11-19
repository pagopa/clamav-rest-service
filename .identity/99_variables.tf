#
# general
#

variable "prefix" {
  type = string
  validation {
    condition = (
      length(var.prefix) <= 6
    )
    error_message = "Max length is 6 chars."
  }
}

variable "env" {
  type = string
  validation {
    condition = (
      length(var.env) <= 4
    )
    error_message = "Max length is 4 chars."
  }
}

variable "env_short" {
  type = string
  validation {
    condition = (
      length(var.env_short) <= 1
    )
    error_message = "Max length is 1 chars."
  }
}

variable "location" {
  type    = string
  default = "westeurope"
}

variable "location_short" {
  type        = string
  description = "Location short like eg: neu, weu.."
}

variable "tags" {
  type = map(any)
  default = {
    CreatedBy = "Terraform"
  }
}

variable "app_resource_group_name" {
  type        = string
  description = "Name of the existing resource group of the app service"
}

variable "identity_resource_group_name" {
  type        = string
  description = "Name of the existing resource group of identities"
}

#
# app
#
variable "app_name" {
  type        = string
  description = "Name of the existing app service to deploy"
}

#
# github
#
variable "github" {
  type = object({
    org         = string
    repository  = string
    environment = string
  })
  description = "GitHub repository"
}

variable "deployments" {
  type = object({
    review_required = bool
    reviewer_teams  = optional(list(string), [])
    reviewer_users  = optional(list(string), [])
  })
  default = {
    review_required = false
    reviewer_teams  = []
    reviewer_users  = []
  }
  description = "Configure deployments for the current environment"
}
