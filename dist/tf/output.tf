output "ami_id" {
  value = data.aws_ami.amazon_linux_2023.id
}

output "node_ips" {
  value = aws_instance.node[*].public_ip
}
