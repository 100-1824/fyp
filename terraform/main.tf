# ============================================================================
# Azure DIDS Infrastructure - Main Configuration
# ============================================================================

terraform {
  required_version = ">= 1.5.0"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.23"
    }
  }

  backend "azurerm" {
    resource_group_name  = "terraform-state-rg"
    storage_account_name = "didsterraformstate"
    container_name       = "tfstate"
    key                  = "dids.terraform.tfstate"
  }
}

provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
  subscription_id = var.subscription_id
}

# ============================================================================
# Resource Group
# ============================================================================

resource "azurerm_resource_group" "dids" {
  name     = var.resource_group_name
  location = var.location
  tags     = merge(var.tags, { Component = "Infrastructure" })
}

# ============================================================================
# Virtual Network
# ============================================================================

resource "azurerm_virtual_network" "dids" {
  name                = "dids-vnet"
  address_space       = var.vnet_address_space
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  tags                = var.tags
}

resource "azurerm_subnet" "aks" {
  name                 = "aks-subnet"
  resource_group_name  = azurerm_resource_group.dids.name
  virtual_network_name = azurerm_virtual_network.dids.name
  address_prefixes     = [var.aks_subnet_address_prefix]
}

resource "azurerm_subnet" "db" {
  name                 = "db-subnet"
  resource_group_name  = azurerm_resource_group.dids.name
  virtual_network_name = azurerm_virtual_network.dids.name
  address_prefixes     = [var.db_subnet_address_prefix]

  delegation {
    name = "fs"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

# ============================================================================
# Network Security Groups
# ============================================================================

resource "azurerm_network_security_group" "aks" {
  name                = "aks-nsg"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  tags                = var.tags

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

# ============================================================================
# Log Analytics Workspace
# ============================================================================

resource "azurerm_log_analytics_workspace" "dids" {
  name                = "dids-logs"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  sku                 = var.log_analytics_sku
  retention_in_days   = var.log_retention_days
  tags                = var.tags
}

# ============================================================================
# Application Insights
# ============================================================================

resource "azurerm_application_insights" "dids" {
  name                = "dids-appinsights"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  workspace_id        = azurerm_log_analytics_workspace.dids.id
  application_type    = "web"
  tags                = var.tags
}

# ============================================================================
# Azure Kubernetes Service (AKS)
# ============================================================================

resource "azurerm_kubernetes_cluster" "dids" {
  name                = "dids-aks-cluster"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  dns_prefix          = "didssecurity"
  kubernetes_version  = var.kubernetes_version
  tags                = var.tags

  default_node_pool {
    name                = "default"
    node_count          = var.node_count
    vm_size             = var.node_vm_size
    vnet_subnet_id      = azurerm_subnet.aks.id
    enable_auto_scaling = var.enable_auto_scaling
    min_count           = var.enable_auto_scaling ? var.min_node_count : null
    max_count           = var.enable_auto_scaling ? var.max_node_count : null
    os_disk_size_gb     = 128
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin     = "azure"
    network_policy     = "azure"
    load_balancer_sku  = "standard"
    service_cidr       = "10.1.0.0/16"
    dns_service_ip     = "10.1.0.10"
  }

  oms_agent {
    log_analytics_workspace_id = azurerm_log_analytics_workspace.dids.id
  }

  azure_policy_enabled = true

  lifecycle {
    ignore_changes = [
      default_node_pool[0].node_count
    ]
  }
}

# ============================================================================
# PostgreSQL Flexible Server
# ============================================================================

resource "azurerm_postgresql_flexible_server" "dids" {
  name                   = "dids-postgresql"
  resource_group_name    = azurerm_resource_group.dids.name
  location               = azurerm_resource_group.dids.location
  version                = var.postgres_version
  delegated_subnet_id    = azurerm_subnet.db.id
  administrator_login    = var.postgres_admin_user
  administrator_password = var.postgres_admin_password
  zone                   = "1"
  storage_mb             = var.postgres_storage_mb
  sku_name               = var.postgres_sku_name
  backup_retention_days  = 7
  geo_redundant_backup_enabled = true
  tags                   = var.tags
}

resource "azurerm_postgresql_flexible_server_database" "dids" {
  name      = "dids"
  server_id = azurerm_postgresql_flexible_server.dids.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

# ============================================================================
# Redis Cache
# ============================================================================

resource "azurerm_redis_cache" "dids" {
  name                = "dids-redis"
  location            = azurerm_resource_group.dids.location
  resource_group_name = azurerm_resource_group.dids.name
  capacity            = var.redis_capacity
  family              = var.redis_family
  sku_name            = var.redis_sku_name
  enable_non_ssl_port = false
  minimum_tls_version = "1.2"
  tags                = var.tags

  redis_configuration {
    maxmemory_policy = "allkeys-lru"
  }
}

# ============================================================================
# Storage Account
# ============================================================================

resource "azurerm_storage_account" "dids" {
  name                     = "didsstorage${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.dids.name
  location                 = azurerm_resource_group.dids.location
  account_tier             = var.storage_account_tier
  account_replication_type = var.storage_replication_type
  tags                     = var.tags
}

resource "random_string" "suffix" {
  length  = 6
  special = false
  upper   = false
}

resource "azurerm_storage_container" "models" {
  name                  = "ml-models"
  storage_account_name  = azurerm_storage_account.dids.name
  container_access_type = "private"
}

resource "azurerm_storage_container" "pcaps" {
  name                  = "pcap-files"
  storage_account_name  = azurerm_storage_account.dids.name
  container_access_type = "private"
}

# ============================================================================
# Key Vault
# ============================================================================

data "azurerm_client_config" "current" {}

resource "azurerm_key_vault" "dids" {
  name                       = "dids-kv-${random_string.suffix.result}"
  location                   = azurerm_resource_group.dids.location
  resource_group_name        = azurerm_resource_group.dids.name
  tenant_id                  = data.azurerm_client_config.current.tenant_id
  sku_name                   = "standard"
  soft_delete_retention_days = 7
  purge_protection_enabled   = false
  tags                       = var.tags

  access_policy {
    tenant_id = data.azurerm_client_config.current.tenant_id
    object_id = data.azurerm_client_config.current.object_id

    secret_permissions = [
      "Get", "List", "Set", "Delete", "Purge"
    ]
  }
}

# ============================================================================
# Outputs
# ============================================================================

output "resource_group_name" {
  value = azurerm_resource_group.dids.name
}

output "aks_cluster_name" {
  value = azurerm_kubernetes_cluster.dids.name
}

output "aks_kubeconfig" {
  value     = azurerm_kubernetes_cluster.dids.kube_config_raw
  sensitive = true
}

output "postgres_fqdn" {
  value = azurerm_postgresql_flexible_server.dids.fqdn
}

output "redis_hostname" {
  value = azurerm_redis_cache.dids.hostname
}

output "storage_account_name" {
  value = azurerm_storage_account.dids.name
}

output "key_vault_uri" {
  value = azurerm_key_vault.dids.vault_uri
}
