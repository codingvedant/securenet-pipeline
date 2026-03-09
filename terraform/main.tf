# ─────────────────────────────────────────
# TERRAFORM CONFIGURATION
# ─────────────────────────────────────────

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Tell Terraform which AWS region to use
provider "aws" {
  region = var.aws_region
}

# ─────────────────────────────────────────
# DATA SOURCES
# Get info about existing AWS resources
# ─────────────────────────────────────────

# Get the latest Amazon Linux 2 AMI
# AMI = Amazon Machine Image = the OS for your EC2
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# ─────────────────────────────────────────
# NETWORKING — VPC
# Your private isolated network on AWS
# ─────────────────────────────────────────

# Create VPC — your private network
resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name        = "${var.project_name}-vpc"
    Environment = var.environment
    Project     = var.project_name
  }
}

# Create public subnet inside the VPC
# This is where your EC2 will live
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidr
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name        = "${var.project_name}-public-subnet"
    Environment = var.environment
  }
}

# Internet Gateway — connects your VPC to the internet
# Without this nothing in your VPC can reach the internet
resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name        = "${var.project_name}-igw"
    Environment = var.environment
  }
}

# Route table — rules for how traffic flows
# This rule sends all internet traffic through the gateway
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name        = "${var.project_name}-public-rt"
    Environment = var.environment
  }
}

# Associate route table with subnet
resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# ─────────────────────────────────────────
# SECURITY GROUP — Virtual Firewall
# Controls what traffic can reach your EC2
# ─────────────────────────────────────────

resource "aws_security_group" "scanner" {
  name        = "${var.project_name}-scanner-sg"
  description = "Security group for SecureNet scanner"
  vpc_id      = aws_vpc.main.id

  # INBOUND RULES — what traffic can come IN

  # Allow SSH from anywhere — for initial setup
  # In production you'd restrict this to your IP only
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "SSH access"
  }

  # Allow HTTP traffic
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access"
  }

  # Allow HTTPS traffic
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  # OUTBOUND RULES — what traffic can go OUT
  # Allow all outbound — EC2 needs internet to pull Docker images
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allow all outbound traffic"
  }

  tags = {
    Name        = "${var.project_name}-scanner-sg"
    Environment = var.environment
  }
}

# ─────────────────────────────────────────
# IAM ROLE — Permissions for EC2
# Lets your EC2 talk to other AWS services
# ─────────────────────────────────────────

# The role itself
resource "aws_iam_role" "ec2_role" {
  name = "${var.project_name}-ec2-role"

  # Trust policy — allows EC2 to assume this role
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

  tags = {
    Name        = "${var.project_name}-ec2-role"
    Environment = var.environment
  }
}

# Attach ECR policy — lets EC2 pull Docker images from ECR
resource "aws_iam_role_policy_attachment" "ecr_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

# Attach CloudWatch policy — lets EC2 send logs to CloudWatch
resource "aws_iam_role_policy_attachment" "cloudwatch_policy" {
  role       = aws_iam_role.ec2_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

# Instance profile — wraps the role so EC2 can use it
resource "aws_iam_instance_profile" "ec2_profile" {
  name = "${var.project_name}-ec2-profile"
  role = aws_iam_role.ec2_role.name
}

# ─────────────────────────────────────────
# EC2 INSTANCE — Your Cloud Server
# ─────────────────────────────────────────

resource "aws_instance" "scanner" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = var.instance_type
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.scanner.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  # User data — commands that run when EC2 first starts
  # This installs Docker automatically on boot
  user_data = <<-EOF
    #!/bin/bash
    yum update -y
    yum install -y docker git
    systemctl start docker
    systemctl enable docker
    usermod -a -G docker ec2-user
    echo "SecureNet scanner instance ready" > /tmp/ready.txt
  EOF

  tags = {
    Name        = "${var.project_name}-scanner"
    Environment = var.environment
    Project     = var.project_name
  }
}

# ─────────────────────────────────────────
# ECR — Private Docker Registry
# Stores your Docker images on AWS
# ─────────────────────────────────────────

resource "aws_ecr_repository" "securenet" {
  name                 = var.project_name
  image_tag_mutability = "MUTABLE"

  # Scan images automatically when pushed
  image_scanning_configuration {
    scan_on_push = true
  }

  tags = {
    Name        = "${var.project_name}-ecr"
    Environment = var.environment
  }
}

# ECR lifecycle policy — automatically delete old images
# Keeps only the 5 most recent images to save storage costs
resource "aws_ecr_lifecycle_policy" "securenet" {
  repository = aws_ecr_repository.securenet.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep last 5 images"
        selection = {
          tagStatus   = "any"
          countType   = "imageCountMoreThan"
          countNumber = 5
        }
        action = {
          type = "expire"
        }
      }
    ]
  })
}