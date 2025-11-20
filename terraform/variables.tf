# ============================================================================
# Azure DIDS Infrastructure Variables
# ============================================================================

variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
  default     = "9fe14c7a-a14a-423e-8b3c-d59b3153d293"
}

variable "resource_group_name" {
  description = "Name of the resource group"
  type        = string
  default     = "DIDS-ResourceGroup"
}

variable "location" {
  description = "Azure region"
  type        = string
  default     = "East US"
}

variable "environment" {
  description = "Environment (dev, staging, production)"
  type        = string
  default     = "production"
}

# ============================================================================
# Kubernetes Cluster Variables
# ============================================================================

variable "kubernetes_version" {
  description = "Kubernetes version"
  type        = string
  default     = "1.28"
}

variable "node_count" {
  description = "Number of nodes in the default node pool"
  type        = number
  default     = 3
}

variable "node_vm_size" {
  description = "VM size for nodes"
  type        = string
  default     = "Standard_DS3_v2"
}

variable "enable_auto_scaling" {
  description = "Enable auto-scaling"
  type        = bool
  default     = true
}

variable "min_node_count" {
  description = "Minimum number of nodes"
  type        = number
  default     = 2
}

variable "max_node_count" {
  description = "Maximum number of nodes"
  type        = number
  default     = 10
}

# ============================================================================
# Database Variables
# ============================================================================

variable "postgres_sku_name" {
  description = "PostgreSQL SKU"
  type        = string
  default     = "GP_Gen5_2"
}

variable "postgres_storage_mb" {
  description = "PostgreSQL storage in MB"
  type        = number
  default     = 51200  # 50 GB
}

variable "postgres_version" {
  description = "PostgreSQL version"
  type        = string
  default     = "15"
}

variable "postgres_admin_user" {
  description = "PostgreSQL admin username"
  type        = string
  default     = "didsadmin"
  sensitive   = true
}

variable "postgres_admin_password" {
  description = "PostgreSQL admin password"
  type        = string
  sensitive   = true
}

# ============================================================================
# Redis Cache Variables
# ============================================================================

variable "redis_capacity" {
  description = "Redis cache capacity"
  type        = number
  default     = 1
}

variable "redis_family" {
  description = "Redis cache family"
  type        = string
  default     = "C"
}

variable "redis_sku_name" {
  description = "Redis cache SKU"
  type        = string
  default     = "Standard"
}

# ============================================================================
# Storage Variables
# ============================================================================

variable "storage_account_tier" {
  description = "Storage account tier"
  type        = string
  default     = "Standard"
}

variable "storage_replication_type" {
  description = "Storage replication type"
  type        = string
  default     = "GRS"
}

# ============================================================================
# Network Variables
# ============================================================================

variable "vnet_address_space" {
  description = "Virtual network address space"
  type        = list(string)
  default     = ["10.0.0.0/16"]
}

variable "aks_subnet_address_prefix" {
  description = "AKS subnet address prefix"
  type        = string
  default     = "10.0.1.0/24"
}

variable "db_subnet_address_prefix" {
  description = "Database subnet address prefix"
  type        = string
  default     = "10.0.2.0/24"
}

variable "gateway_subnet_address_prefix" {
  description = "Gateway subnet address prefix"
  type        = string
  default     = "10.0.3.0/24"
}

# ============================================================================
# Monitoring Variables
# ============================================================================

variable "log_analytics_sku" {
  description = "Log Analytics workspace SKU"
  type        = string
  default     = "PerGB2018"
}

variable "log_retention_days" {
  description = "Log retention in days"
  type        = number
  default     = 30
}

# ============================================================================
# Security Variables
# ============================================================================

variable "allowed_ip_ranges" {
  description = "Allowed IP ranges for access"
  type        = list(string)
  default     = []
}

variable "enable_private_cluster" {
  description = "Enable private AKS cluster"
  type        = bool
  default     = false
}

# ============================================================================
# Tags
# ============================================================================

variable "tags" {
  description = "Resource tags"
  type        = map(string)
  default = {
    Project     = "DIDS"
    ManagedBy   = "Terraform"
    Environment = "Production"
  }
}
