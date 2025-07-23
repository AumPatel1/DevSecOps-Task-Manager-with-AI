# Terraform Variables for DevSecOps Infrastructure

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "eu-west-2"
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Project name"
  type        = string
  default     = "devsecops"
}

variable "vpc_cidr" {
  description = "CIDR block for VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidr" {
  description = "CIDR block for public subnet"
  type        = string
  default     = "10.0.1.0/24"
}

variable "private_subnet_cidr" {
  description = "CIDR block for private subnet"
  type        = string
  default     = "10.0.2.0/24"
}

variable "allowed_cidr" {
  description = "CIDR block allowed to access Jenkins"
  type        = string
  default     = "0.0.0.0/0"  # Change this to your IP range
}

variable "bastion_cidr" {
  description = "CIDR block for bastion host"
  type        = string
  default     = "0.0.0.0/0"  # Change this to your bastion IP
}

variable "jenkins_instance_type" {
  description = "EC2 instance type for Jenkins"
  type        = string
  default     = "t3.medium"
}

variable "jenkins_password" {
  description = "Jenkins admin password"
  type        = string
  sensitive   = true
}

variable "domain_name" {
  description = "Domain name for Jenkins"
  type        = string
  default     = ""
}

variable "ssh_public_key_path" {
  description = "Path to SSH public key"
  type        = string
  default     = "~/.ssh/id_rsa.pub"
}

variable "jenkins_plugins" {
  description = "List of Jenkins plugins to install"
  type        = list(string)
  default = [
    "pipeline-model-definition",
    "git",
    "docker-workflow",
    "credentials-binding",
    "timestamper",
    "ws-cleanup",
    "email-ext",
    "slack",
    "prometheus",
    "blueocean",
    "workflow-aggregator",
    "matrix-auth",
    "build-timeout",
    "ansible",
    "terraform"
  ]
}

variable "monitoring_enabled" {
  description = "Enable monitoring stack"
  type        = bool
  default     = true
}

variable "backup_enabled" {
  description = "Enable automated backups"
  type        = bool
  default     = true
}

variable "backup_retention_days" {
  description = "Number of days to retain backups"
  type        = number
  default     = 30
}

variable "ssl_certificate_arn" {
  description = "ARN of SSL certificate for HTTPS"
  type        = string
  default     = ""
}

variable "tags" {
  description = "Additional tags for resources"
  type        = map(string)
  default = {
    Owner       = "Security Team"
    CostCenter  = "Security"
    Environment = "Production"
  }
} 