# Variables for Privix Node Infrastructure Module

variable "environment" {
  description = "Environment name (e.g., production, staging, development)"
  type        = string
  validation {
    condition = contains(["production", "staging", "development"], var.environment)
    error_message = "Environment must be one of: production, staging, development."
  }
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# Networking Variables
variable "vpc_id" {
  description = "VPC ID where resources will be created (if null, a new VPC will be created)"
  type        = string
  default     = null
}

variable "vpc_cidr" {
  description = "CIDR block for VPC (used only if vpc_id is null)"
  type        = string
  default     = "10.0.0.0/16"
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (used only if vpc_id is null)"
  type        = list(string)
  default     = ["10.0.101.0/24", "10.0.102.0/24", "10.0.103.0/24"]
}

# Security Variables
variable "allowed_p2p_cidrs" {
  description = "CIDR blocks allowed for P2P networking"
  type        = list(string)
  default     = ["0.0.0.0/0"]
}

variable "allowed_rpc_cidrs" {
  description = "CIDR blocks allowed for RPC access"
  type        = list(string)
  default     = ["10.0.0.0/8"]
}

variable "admin_ssh_cidrs" {
  description = "CIDR blocks allowed for SSH access to bastion"
  type        = list(string)
  default     = []
}

# Instance Configuration
variable "ami_id" {
  description = "AMI ID for Privix node instances"
  type        = string
}

variable "instance_type" {
  description = "EC2 instance type for Privix nodes"
  type        = string
  default     = "c5.xlarge"
  validation {
    condition = can(regex("^[a-z][0-9]+[a-z]*\\.[a-z0-9]+$", var.instance_type))
    error_message = "Instance type must be a valid EC2 instance type."
  }
}

variable "key_pair_name" {
  description = "EC2 Key Pair name for SSH access"
  type        = string
}

variable "root_volume_size" {
  description = "Size of root volume in GB"
  type        = number
  default     = 50
}

variable "data_volume_size" {
  description = "Size of data volume in GB"
  type        = number
  default     = 500
}

variable "data_volume_throughput" {
  description = "Throughput for data volume (MB/s)"
  type        = number
  default     = 250
}

variable "data_volume_iops" {
  description = "IOPS for data volume"
  type        = number
  default     = 3000
}

# Auto Scaling Configuration
variable "min_nodes" {
  description = "Minimum number of nodes in the cluster"
  type        = number
  default     = 1
}

variable "max_nodes" {
  description = "Maximum number of nodes in the cluster"
  type        = number
  default     = 5
}

variable "desired_nodes" {
  description = "Desired number of nodes in the cluster"
  type        = number
  default     = 3
}

# Load Balancer Configuration
variable "internal_load_balancer" {
  description = "Whether the load balancer should be internal"
  type        = bool
  default     = true
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate for HTTPS listener"
  type        = string
}

# Blockchain Configuration
variable "chain_id" {
  description = "Blockchain chain ID"
  type        = number
}

variable "network_name" {
  description = "Blockchain network name"
  type        = string
}

variable "genesis_hash" {
  description = "Genesis block hash"
  type        = string
}

variable "bootstrap_peers" {
  description = "List of bootstrap peer addresses"
  type        = list(string)
  default     = []
}

variable "rpc_endpoints" {
  description = "List of RPC endpoint URLs"
  type        = list(string)
  default     = []
}

# Port Configuration
variable "p2p_port" {
  description = "Port for P2P networking"
  type        = number
  default     = 10001
}

variable "rpc_port" {
  description = "Port for JSON-RPC API"
  type        = number
  default     = 8545
}

variable "grpc_port" {
  description = "Port for gRPC API"
  type        = number
  default     = 9632
}

variable "metrics_port" {
  description = "Port for metrics endpoint"
  type        = number
  default     = 5001
}

# Cryptographic Keys (should be provided via external secrets)
variable "validator_private_key" {
  description = "Validator private key (base64 encoded)"
  type        = string
  sensitive   = true
  validation {
    condition = can(base64decode(var.validator_private_key))
    error_message = "Validator private key must be base64 encoded."
  }
}

variable "network_private_key" {
  description = "Network private key (base64 encoded)"
  type        = string
  sensitive   = true
  validation {
    condition = can(base64decode(var.network_private_key))
    error_message = "Network private key must be base64 encoded."
  }
}

# Monitoring and Logging
variable "log_retention_days" {
  description = "CloudWatch log retention in days"
  type        = number
  default     = 30
  validation {
    condition = contains([1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1827, 3653], var.log_retention_days)
    error_message = "Log retention days must be a valid CloudWatch log retention value."
  }
}

variable "enable_drift_detection" {
  description = "Enable AWS Config for drift detection"
  type        = bool
  default     = true
}

# Backup and Recovery
variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

variable "enable_point_in_time_recovery" {
  description = "Enable point-in-time recovery for data volumes"
  type        = bool
  default     = true
}

# Compliance and Security
variable "enable_encryption_at_rest" {
  description = "Enable encryption at rest for all storage"
  type        = bool
  default     = true
}

variable "enable_encryption_in_transit" {
  description = "Enable encryption in transit"
  type        = bool
  default     = true
}

variable "compliance_mode" {
  description = "Compliance mode (standard, high, critical)"
  type        = string
  default     = "high"
  validation {
    condition = contains(["standard", "high", "critical"], var.compliance_mode)
    error_message = "Compliance mode must be one of: standard, high, critical."
  }
}

# Multi-Region Configuration
variable "enable_cross_region_backup" {
  description = "Enable cross-region backup replication"
  type        = bool
  default     = false
}

variable "backup_destination_region" {
  description = "Destination region for cross-region backups"
  type        = string
  default     = "us-west-2"
}

# Disaster Recovery
variable "enable_disaster_recovery" {
  description = "Enable disaster recovery setup"
  type        = bool
  default     = false
}

variable "recovery_time_objective_minutes" {
  description = "Recovery Time Objective in minutes"
  type        = number
  default     = 60
}

variable "recovery_point_objective_minutes" {
  description = "Recovery Point Objective in minutes"
  type        = number
  default     = 15
}

# Performance Tuning
variable "enable_enhanced_monitoring" {
  description = "Enable enhanced monitoring for instances"
  type        = bool
  default     = true
}

variable "monitoring_interval" {
  description = "Monitoring interval in seconds"
  type        = number
  default     = 60
  validation {
    condition = contains([1, 5, 10, 15, 30, 60], var.monitoring_interval)
    error_message = "Monitoring interval must be one of: 1, 5, 10, 15, 30, 60."
  }
}

# Cost Optimization
variable "enable_spot_instances" {
  description = "Enable spot instances for cost optimization"
  type        = bool
  default     = false
}

variable "spot_instance_interruption_behavior" {
  description = "Behavior when spot instance is interrupted"
  type        = string
  default     = "terminate"
  validation {
    condition = contains(["terminate", "stop", "hibernate"], var.spot_instance_interruption_behavior)
    error_message = "Spot instance interruption behavior must be one of: terminate, stop, hibernate."
  }
}

variable "enable_scheduled_scaling" {
  description = "Enable scheduled scaling for cost optimization"
  type        = bool
  default     = false
}

# Development and Testing
variable "enable_debug_mode" {
  description = "Enable debug mode (for development environments only)"
  type        = bool
  default     = false
}

variable "allow_ssh_from_internet" {
  description = "Allow SSH access from internet (for development environments only)"
  type        = bool
  default     = false
}

variable "enable_public_rpc" {
  description = "Enable public RPC access (for development environments only)"
  type        = bool
  default     = false
}

# Resource Naming
variable "resource_prefix" {
  description = "Prefix for resource names"
  type        = string
  default     = "privix"
  validation {
    condition = can(regex("^[a-zA-Z][a-zA-Z0-9-]*$", var.resource_prefix))
    error_message = "Resource prefix must start with a letter and contain only letters, numbers, and hyphens."
  }
}

variable "resource_suffix" {
  description = "Suffix for resource names"
  type        = string
  default     = ""
}

# Feature Flags
variable "feature_flags" {
  description = "Feature flags for experimental features"
  type        = map(bool)
  default     = {
    enable_ipv6                    = false
    enable_nitro_enclaves         = false
    enable_dedicated_hosts        = false
    enable_placement_groups       = false
    enable_elastic_fabric_adapter = false
  }
}

# Advanced Security
variable "enable_guarduty" {
  description = "Enable Amazon GuardDuty for threat detection"
  type        = bool
  default     = true
}

variable "enable_macie" {
  description = "Enable Amazon Macie for data discovery and classification"
  type        = bool
  default     = false
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub for security posture management"
  type        = bool
  default     = true
}

variable "security_contact_email" {
  description = "Email address for security notifications"
  type        = string
  default     = ""
  validation {
    condition = var.security_contact_email == "" || can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.security_contact_email))
    error_message = "Security contact email must be a valid email address."
  }
} 