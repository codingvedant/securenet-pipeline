# ─────────────────────────────────────────
# OUTPUTS
# Printed after terraform apply completes
# Useful info you need to connect to resources
# ─────────────────────────────────────────

output "vpc_id" {
  description = "ID of the VPC"
  value       = aws_vpc.main.id
}

output "ec2_public_ip" {
  description = "Public IP of your EC2 instance"
  value       = aws_instance.scanner.public_ip
}

output "ec2_public_dns" {
  description = "Public DNS of your EC2 instance"
  value       = aws_instance.scanner.public_dns
}

output "ecr_repository_url" {
  description = "URL of your ECR Docker registry"
  value       = aws_ecr_repository.securenet.repository_url
}

output "security_group_id" {
  description = "ID of the security group"
  value       = aws_security_group.scanner.id
}

output "ssh_command" {
  description = "Command to SSH into your EC2"
  value       = "ssh -i securenet-key.pem ec2-user@${aws_instance.scanner.public_ip}"
}