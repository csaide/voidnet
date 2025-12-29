module "vpc" {
  source = "terraform-aws-modules/vpc/aws"

  name = var.vpc_name
  cidr = var.vpc_cidr

  azs            = [var.az_name]
  public_subnets = [var.vpc_cidr]

  enable_ipv6                                   = true
  public_subnet_assign_ipv6_address_on_creation = true
  public_subnet_ipv6_prefixes                   = [0]

  tags = {
    Terraform   = "true"
    Environment = "dev"
  }
}

data "http" "my_ip" {
  url = "https://icanhazip.com/v4"
}

resource "aws_security_group" "xdp" {
  name        = "${var.vpc_name}-xdp"
  description = "Allow XDP testing traffic"
  vpc_id      = module.vpc.vpc_id

  ingress {
    description = "SSH from my machine"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${chomp(data.http.my_ip.response_body)}/32"]
  }

  ingress {
    description = "IPv4 XDP testing traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [module.vpc.vpc_cidr_block]
  }

  ingress {
    description = "IPv6 XDP testing traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = [module.vpc.vpc_ipv6_cidr_block]
  }

  egress {
    description = "IPv4 egress traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {  
    description = "IPv6 egress traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    ipv6_cidr_blocks = ["::/0"]
  }
}

data "aws_ami" "amazon_linux_2023" {
  most_recent = true
  name_regex  = "debian-13-arm64.*"
  owners      = ["amazon"]

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }

  filter {
    name   = "architecture"
    values = ["arm64"]
  }

  filter {
    name = "ena-support"
    values = ["true"]
  }
}

resource "aws_key_pair" "xdp" {
  key_name   = "${var.vpc_name}-xdp"
  public_key = file(var.public_key_path)
}

resource "aws_instance" "node" {
  count                       = var.node_count
  ami                         = data.aws_ami.amazon_linux_2023.id
  instance_type               = var.instance_type
  subnet_id                   = module.vpc.public_subnets[0]
  key_name                    = aws_key_pair.xdp.key_name
  associate_public_ip_address = true
  security_groups = [aws_security_group.xdp.id]
}

resource "aws_network_interface" "secondary" {
  count           = 2
  subnet_id       = module.vpc.public_subnets[0]
  security_groups = [aws_security_group.xdp.id]

  attachment {
    instance     = aws_instance.node[count.index].id
    device_index = 1
  }
}
