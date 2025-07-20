# Privix Node Infrastructure Module
# This module creates a secure, immutable infrastructure for Privix blockchain nodes
# with comprehensive monitoring, drift detection, and compliance controls

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.4"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
    local = {
      source  = "hashicorp/local"
      version = "~> 2.4"
    }
  }
}

# Data sources for security and compliance
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

# Generate secure random identifiers
resource "random_id" "deployment" {
  byte_length = 8
}

resource "random_password" "node_secret" {
  length  = 32
  special = true
}

# Local values for configuration
locals {
  deployment_id = random_id.deployment.hex
  common_tags = merge(var.common_tags, {
    Environment      = var.environment
    Project          = "privix-blockchain"
    DeploymentId     = local.deployment_id
    ManagedBy        = "terraform"
    SecurityLevel    = "high"
    ComplianceScope  = "production"
    DriftDetection   = "enabled"
    ImmutableInfra   = "true"
    BackupStrategy   = "automated"
    MonitoringLevel  = "comprehensive"
  })
  
  # Security groups rules
  node_ports = {
    p2p_port     = var.p2p_port
    rpc_port     = var.rpc_port
    grpc_port    = var.grpc_port
    metrics_port = var.metrics_port
  }
}

# KMS Key for encryption at rest and in transit
resource "aws_kms_key" "privix_node" {
  description             = "KMS key for Privix node encryption - ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "EnableFullAccess"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowPrivixNodeAccess"
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.privix_node.arn
        }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = "*"
      }
    ]
  })

  tags = merge(local.common_tags, {
    Name        = "privix-node-kms-${var.environment}"
    Purpose     = "encryption"
    KeyRotation = "enabled"
  })
}

resource "aws_kms_alias" "privix_node" {
  name          = "alias/privix-node-${var.environment}-${local.deployment_id}"
  target_key_id = aws_kms_key.privix_node.key_id
}

# VPC and Networking (if not provided)
resource "aws_vpc" "privix" {
  count = var.vpc_id == null ? 1 : 0
  
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  tags = merge(local.common_tags, {
    Name = "privix-vpc-${var.environment}"
    Type = "isolated-network"
  })
}

resource "aws_internet_gateway" "privix" {
  count = var.vpc_id == null ? 1 : 0
  
  vpc_id = aws_vpc.privix[0].id
  
  tags = merge(local.common_tags, {
    Name = "privix-igw-${var.environment}"
  })
}

resource "aws_subnet" "private" {
  count = length(var.private_subnet_cidrs)
  
  vpc_id            = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = merge(local.common_tags, {
    Name = "privix-private-subnet-${count.index + 1}-${var.environment}"
    Type = "private"
    Tier = "application"
  })
}

resource "aws_subnet" "public" {
  count = var.vpc_id == null ? length(var.public_subnet_cidrs) : 0
  
  vpc_id                  = aws_vpc.privix[0].id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true
  
  tags = merge(local.common_tags, {
    Name = "privix-public-subnet-${count.index + 1}-${var.environment}"
    Type = "public"
    Tier = "dmz"
  })
}

# NAT Gateway for private subnet internet access
resource "aws_eip" "nat" {
  count = var.vpc_id == null ? length(var.public_subnet_cidrs) : 0
  
  domain = "vpc"
  
  tags = merge(local.common_tags, {
    Name = "privix-nat-eip-${count.index + 1}-${var.environment}"
  })
  
  depends_on = [aws_internet_gateway.privix]
}

resource "aws_nat_gateway" "privix" {
  count = var.vpc_id == null ? length(var.public_subnet_cidrs) : 0
  
  allocation_id = aws_eip.nat[count.index].id
  subnet_id     = aws_subnet.public[count.index].id
  
  tags = merge(local.common_tags, {
    Name = "privix-nat-gateway-${count.index + 1}-${var.environment}"
  })
  
  depends_on = [aws_internet_gateway.privix]
}

# Route tables
resource "aws_route_table" "private" {
  count = length(var.private_subnet_cidrs)
  
  vpc_id = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  
  dynamic "route" {
    for_each = var.vpc_id == null ? [1] : []
    content {
      cidr_block     = "0.0.0.0/0"
      nat_gateway_id = aws_nat_gateway.privix[count.index % length(aws_nat_gateway.privix)].id
    }
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-private-rt-${count.index + 1}-${var.environment}"
    Type = "private"
  })
}

resource "aws_route_table_association" "private" {
  count = length(var.private_subnet_cidrs)
  
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[count.index].id
}

# Security Groups
resource "aws_security_group" "privix_node" {
  name_prefix = "privix-node-${var.environment}-"
  vpc_id      = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  description = "Security group for Privix blockchain nodes"
  
  # P2P networking
  ingress {
    description = "P2P networking"
    from_port   = local.node_ports.p2p_port
    to_port     = local.node_ports.p2p_port
    protocol    = "tcp"
    cidr_blocks = var.allowed_p2p_cidrs
  }
  
  # JSON-RPC API (restricted)
  ingress {
    description = "JSON-RPC API"
    from_port   = local.node_ports.rpc_port
    to_port     = local.node_ports.rpc_port
    protocol    = "tcp"
    cidr_blocks = var.allowed_rpc_cidrs
  }
  
  # gRPC API (internal only)
  ingress {
    description     = "gRPC API"
    from_port       = local.node_ports.grpc_port
    to_port         = local.node_ports.grpc_port
    protocol        = "tcp"
    security_groups = [aws_security_group.internal.id]
  }
  
  # Metrics endpoint (monitoring only)
  ingress {
    description     = "Metrics endpoint"
    from_port       = local.node_ports.metrics_port
    to_port         = local.node_ports.metrics_port
    protocol        = "tcp"
    security_groups = [aws_security_group.monitoring.id]
  }
  
  # SSH access (bastion only)
  ingress {
    description     = "SSH access"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.bastion.id]
  }
  
  # Outbound internet access
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-sg-${var.environment}"
    Type = "application-security-group"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "internal" {
  name_prefix = "privix-internal-${var.environment}-"
  vpc_id      = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  description = "Internal services security group"
  
  tags = merge(local.common_tags, {
    Name = "privix-internal-sg-${var.environment}"
    Type = "internal-security-group"
  })
}

resource "aws_security_group" "monitoring" {
  name_prefix = "privix-monitoring-${var.environment}-"
  vpc_id      = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  description = "Monitoring services security group"
  
  tags = merge(local.common_tags, {
    Name = "privix-monitoring-sg-${var.environment}"
    Type = "monitoring-security-group"
  })
}

resource "aws_security_group" "bastion" {
  name_prefix = "privix-bastion-${var.environment}-"
  vpc_id      = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  description = "Bastion host security group"
  
  ingress {
    description = "SSH from admin networks"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.admin_ssh_cidrs
  }
  
  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-bastion-sg-${var.environment}"
    Type = "bastion-security-group"
  })
}

# IAM Roles and Policies
resource "aws_iam_role" "privix_node" {
  name_prefix = "privix-node-role-${var.environment}-"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
  
  tags = merge(local.common_tags, {
    Name = "privix-node-role-${var.environment}"
    Type = "service-role"
  })
}

resource "aws_iam_role_policy" "privix_node" {
  name_prefix = "privix-node-policy-${var.environment}-"
  role        = aws_iam_role.privix_node.id
  
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = [aws_kms_key.privix_node.arn]
      },
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.node_keys.arn,
          aws_secretsmanager_secret.node_config.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = [
          "${aws_s3_bucket.node_data.arn}/*",
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.node_data.arn,
          aws_s3_bucket.audit_logs.arn
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "cloudwatch:PutMetricData",
          "ec2:DescribeTags",
          "logs:PutLogEvents",
          "logs:CreateLogGroup",
          "logs:CreateLogStream"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "privix_node" {
  name_prefix = "privix-node-profile-${var.environment}-"
  role        = aws_iam_role.privix_node.name
  
  tags = local.common_tags
}

# Secrets Manager for sensitive configuration
resource "aws_secretsmanager_secret" "node_keys" {
  name_prefix             = "privix-node-keys-${var.environment}-"
  description             = "Cryptographic keys for Privix node"
  kms_key_id              = aws_kms_key.privix_node.arn
  recovery_window_in_days = 30
  
  tags = merge(local.common_tags, {
    Name        = "privix-node-keys-${var.environment}"
    Type        = "cryptographic-keys"
    Sensitivity = "high"
  })
}

resource "aws_secretsmanager_secret_version" "node_keys" {
  secret_id = aws_secretsmanager_secret.node_keys.id
  secret_string = jsonencode({
    validator_key = var.validator_private_key
    network_key   = var.network_private_key
    node_secret   = random_password.node_secret.result
  })
}

resource "aws_secretsmanager_secret" "node_config" {
  name_prefix             = "privix-node-config-${var.environment}-"
  description             = "Configuration for Privix node"
  kms_key_id              = aws_kms_key.privix_node.arn
  recovery_window_in_days = 30
  
  tags = merge(local.common_tags, {
    Name = "privix-node-config-${var.environment}"
    Type = "configuration"
  })
}

resource "aws_secretsmanager_secret_version" "node_config" {
  secret_id = aws_secretsmanager_secret.node_config.id
  secret_string = jsonencode({
    chain_id      = var.chain_id
    network_name  = var.network_name
    genesis_hash  = var.genesis_hash
    bootstrap_peers = var.bootstrap_peers
    rpc_endpoints   = var.rpc_endpoints
  })
}

# S3 Buckets for data storage
resource "aws_s3_bucket" "node_data" {
  bucket_prefix = "privix-node-data-${var.environment}-"
  
  tags = merge(local.common_tags, {
    Name    = "privix-node-data-${var.environment}"
    Type    = "blockchain-data"
    Backup  = "enabled"
    Versioning = "enabled"
  })
}

resource "aws_s3_bucket_versioning" "node_data" {
  bucket = aws_s3_bucket.node_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "node_data" {
  bucket = aws_s3_bucket.node_data.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.privix_node.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
}

resource "aws_s3_bucket_public_access_block" "node_data" {
  bucket = aws_s3_bucket.node_data.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket" "audit_logs" {
  bucket_prefix = "privix-audit-logs-${var.environment}-"
  
  tags = merge(local.common_tags, {
    Name      = "privix-audit-logs-${var.environment}"
    Type      = "audit-logs"
    Retention = "7-years"
    WORM      = "enabled"
  })
}

resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  rule {
    default_retention {
      mode = "COMPLIANCE"
      years = 7
    }
  }
  
  depends_on = [aws_s3_bucket_versioning.audit_logs]
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_encryption" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id
  
  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        kms_master_key_id = aws_kms_key.privix_node.arn
        sse_algorithm     = "aws:kms"
      }
    }
  }
}

# Launch Template for immutable infrastructure
resource "aws_launch_template" "privix_node" {
  name_prefix   = "privix-node-${var.environment}-"
  image_id      = var.ami_id
  instance_type = var.instance_type
  key_name      = var.key_pair_name
  
  vpc_security_group_ids = [aws_security_group.privix_node.id]
  
  iam_instance_profile {
    name = aws_iam_instance_profile.privix_node.name
  }
  
  block_device_mappings {
    device_name = "/dev/sda1"
    ebs {
      volume_size           = var.root_volume_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.privix_node.arn
      delete_on_termination = true
    }
  }
  
  block_device_mappings {
    device_name = "/dev/sdf"
    ebs {
      volume_size           = var.data_volume_size
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = aws_kms_key.privix_node.arn
      delete_on_termination = false
      throughput            = var.data_volume_throughput
      iops                  = var.data_volume_iops
    }
  }
  
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    http_put_response_hop_limit = 1
  }
  
  monitoring {
    enabled = true
  }
  
  user_data = base64encode(templatefile("${path.module}/user_data.sh", {
    node_keys_secret   = aws_secretsmanager_secret.node_keys.name
    node_config_secret = aws_secretsmanager_secret.node_config.name
    s3_bucket_data     = aws_s3_bucket.node_data.bucket
    s3_bucket_audit    = aws_s3_bucket.audit_logs.bucket
    kms_key_id         = aws_kms_key.privix_node.arn
    environment        = var.environment
    log_group_name     = aws_cloudwatch_log_group.privix_node.name
    region             = data.aws_region.current.name
  }))
  
  tag_specifications {
    resource_type = "instance"
    tags = merge(local.common_tags, {
      Name = "privix-node-${var.environment}"
      Type = "blockchain-node"
    })
  }
  
  tag_specifications {
    resource_type = "volume"
    tags = merge(local.common_tags, {
      Name = "privix-node-volume-${var.environment}"
      Type = "blockchain-storage"
    })
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-lt-${var.environment}"
  })
  
  lifecycle {
    create_before_destroy = true
  }
}

# Auto Scaling Group for high availability
resource "aws_autoscaling_group" "privix_node" {
  name                = "privix-node-asg-${var.environment}-${local.deployment_id}"
  vpc_zone_identifier = aws_subnet.private[*].id
  target_group_arns   = [aws_lb_target_group.privix_node.arn]
  health_check_type   = "ELB"
  health_check_grace_period = 300
  
  min_size         = var.min_nodes
  max_size         = var.max_nodes
  desired_capacity = var.desired_nodes
  
  launch_template {
    id      = aws_launch_template.privix_node.id
    version = "$Latest"
  }
  
  instance_refresh {
    strategy = "Rolling"
    preferences {
      min_healthy_percentage = 50
      instance_warmup       = 300
    }
    triggers = ["tag"]
  }
  
  dynamic "tag" {
    for_each = local.common_tags
    content {
      key                 = tag.key
      value               = tag.value
      propagate_at_launch = true
    }
  }
  
  tag {
    key                 = "Name"
    value               = "privix-node-asg-${var.environment}"
    propagate_at_launch = false
  }
  
  lifecycle {
    create_before_destroy = true
  }
}

# Application Load Balancer for RPC endpoints
resource "aws_lb" "privix_node" {
  name               = "privix-node-alb-${var.environment}"
  internal           = var.internal_load_balancer
  load_balancer_type = "application"
  security_groups    = [aws_security_group.privix_node.id]
  subnets            = var.internal_load_balancer ? aws_subnet.private[*].id : aws_subnet.public[*].id
  
  enable_deletion_protection = var.environment == "production"
  
  access_logs {
    bucket  = aws_s3_bucket.audit_logs.bucket
    prefix  = "alb-access-logs"
    enabled = true
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-alb-${var.environment}"
    Type = "load-balancer"
  })
}

resource "aws_lb_target_group" "privix_node" {
  name     = "privix-node-tg-${var.environment}"
  port     = local.node_ports.rpc_port
  protocol = "HTTP"
  vpc_id   = var.vpc_id != null ? var.vpc_id : aws_vpc.privix[0].id
  
  health_check {
    enabled             = true
    healthy_threshold   = 2
    interval            = 30
    matcher             = "200"
    path                = "/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    timeout             = 5
    unhealthy_threshold = 2
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-tg-${var.environment}"
  })
}

resource "aws_lb_listener" "privix_node" {
  load_balancer_arn = aws_lb.privix_node.arn
  port              = "443"
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-2-2017-01"
  certificate_arn   = var.ssl_certificate_arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.privix_node.arn
  }
}

# CloudWatch Log Group
resource "aws_cloudwatch_log_group" "privix_node" {
  name              = "/aws/privix-node/${var.environment}"
  retention_in_days = var.log_retention_days
  kms_key_id        = aws_kms_key.privix_node.arn
  
  tags = merge(local.common_tags, {
    Name = "privix-node-logs-${var.environment}"
    Type = "logs"
  })
}

# CloudWatch Alarms for monitoring
resource "aws_cloudwatch_metric_alarm" "high_cpu" {
  alarm_name          = "privix-node-high-cpu-${var.environment}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "CPUUtilization"
  namespace           = "AWS/EC2"
  period              = "120"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors ec2 cpu utilization"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    AutoScalingGroupName = aws_autoscaling_group.privix_node.name
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-cpu-alarm-${var.environment}"
  })
}

resource "aws_cloudwatch_metric_alarm" "node_health" {
  alarm_name          = "privix-node-health-${var.environment}"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "HealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = "60"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors privix node health"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  
  dimensions = {
    TargetGroup  = aws_lb_target_group.privix_node.arn_suffix
    LoadBalancer = aws_lb.privix_node.arn_suffix
  }
  
  tags = merge(local.common_tags, {
    Name = "privix-node-health-alarm-${var.environment}"
  })
}

# SNS Topic for alerts
resource "aws_sns_topic" "alerts" {
  name              = "privix-node-alerts-${var.environment}"
  kms_master_key_id = aws_kms_key.privix_node.arn
  
  tags = merge(local.common_tags, {
    Name = "privix-node-alerts-${var.environment}"
    Type = "notifications"
  })
}

# Drift Detection using AWS Config
resource "aws_config_configuration_recorder" "privix_drift_detection" {
  count    = var.enable_drift_detection ? 1 : 0
  name     = "privix-drift-detector-${var.environment}"
  role_arn = aws_iam_role.config[0].arn
  
  recording_group {
    all_supported                 = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "privix_drift_detection" {
  count           = var.enable_drift_detection ? 1 : 0
  name            = "privix-drift-channel-${var.environment}"
  s3_bucket_name  = aws_s3_bucket.config_bucket[0].bucket
  s3_key_prefix   = "config"
  sns_topic_arn   = aws_sns_topic.config_notifications[0].arn
}

resource "aws_iam_role" "config" {
  count = var.enable_drift_detection ? 1 : 0
  name  = "privix-config-role-${var.environment}"
  
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
  
  tags = local.common_tags
}

resource "aws_iam_role_policy_attachment" "config" {
  count      = var.enable_drift_detection ? 1 : 0
  role       = aws_iam_role.config[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/ConfigRole"
}

resource "aws_s3_bucket" "config_bucket" {
  count         = var.enable_drift_detection ? 1 : 0
  bucket_prefix = "privix-config-${var.environment}-"
  
  tags = merge(local.common_tags, {
    Name = "privix-config-bucket-${var.environment}"
    Type = "configuration-tracking"
  })
}

resource "aws_sns_topic" "config_notifications" {
  count = var.enable_drift_detection ? 1 : 0
  name  = "privix-config-notifications-${var.environment}"
  
  tags = merge(local.common_tags, {
    Name = "privix-config-notifications-${var.environment}"
  })
} 