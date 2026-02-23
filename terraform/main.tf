terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
  required_version = ">= 1.0"
}

provider "aws" {
  region = var.aws_region
}

variable "node_count" {
  description = "Number of nodes to provision"
  type        = number
  default     = 5
}

variable "policy_group" {
  description = "Chef policy group (test, stage, prod)"
  type        = string
  default     = "test"
}

variable "aws_region" {
  description = "AWS region"
  type        = string
  default     = "ap-northeast-3"
}

variable "instance_type" {
  description = "EC2 instance type"
  type        = string
  default     = "t3.micro"
}

variable "chef_server_url" {
  description = "Chef Server URL"
  type        = string
  sensitive   = true
}

variable "chef_org" {
  description = "Chef organization"
  type        = string
}

variable "ssh_key_name" {
  description = "Existing EC2 key pair name for SSH access"
  type        = string
}

variable "run_id" {
  description = "Unique identifier for this provisioning run"
  type        = string
  default     = "manual"
}

# Data source: Find latest Ubuntu 22.04 AMI
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "state"
    values = ["available"]
  }
}

data "aws_key_pair" "bootstrap" {
  key_name = var.ssh_key_name
}

# Security group for Chef nodes
resource "aws_security_group" "chef_nodes" {
  name        = "chef-nodes-${var.policy_group}-${var.run_id}-sg"
  description = "Security group for Chef nodes (${var.policy_group})"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name        = "chef-nodes-${var.policy_group}-${var.run_id}"
    Environment = var.policy_group
    RunId       = var.run_id
  }
}

# EC2 instances
resource "aws_instance" "chef_nodes" {
  count                       = var.node_count
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  key_name                    = data.aws_key_pair.bootstrap.key_name
  security_groups             = [aws_security_group.chef_nodes.name]
  associate_public_ip_address = true

  user_data = filebase64("${path.module}/user-data.sh")

  tags = {
    Name        = "chef-node-${var.policy_group}-${var.run_id}-${count.index + 1}"
    Environment = var.policy_group
    ManagedBy   = "Terraform"
    RunId       = var.run_id
  }

  depends_on = [aws_security_group.chef_nodes]
}

# Outputs
output "instance_ids" {
  description = "IDs of provisioned instances"
  value       = jsonencode(aws_instance.chef_nodes[*].id)
}

output "instance_ips" {
  description = "Public IPs of provisioned instances"
  value       = jsonencode(aws_instance.chef_nodes[*].public_ip)
}

output "instance_details" {
  description = "Details of all provisioned instances"
  value = [
    for instance in aws_instance.chef_nodes : {
      id         = instance.id
      public_ip  = instance.public_ip
      private_ip = instance.private_ip
      tags       = instance.tags
    }
  ]
}
