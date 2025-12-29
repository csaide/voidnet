variable "vpc_cidr" {
  description = "The CIDR block for the VPC"
  type        = string
  default     = "10.10.0.0/16"
}

variable "vpc_name" {
  description = "The name of the VPC"
  type        = string
  default     = "voidnet"
}

variable "az_name" {
  description = "The name of the Availability Zone"
  type        = string
  default     = "us-west-2a"
}

variable "node_count" {
  description = "The number of nodes to create"
  type        = number
  default     = 2
}

variable "instance_type" {
  description = "The type of instance to create"
  type        = string
  default     = "c8gn.2xlarge"
}

variable "public_key_path" {
  description = "The path to the public key to use"
  type        = string
}
