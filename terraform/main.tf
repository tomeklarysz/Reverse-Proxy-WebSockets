terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = "eu-central-1"
}

resource "aws_security_group" "vps_websocket_sg" {
  name = "vps-websocket-sg"

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] 
  }

  ingress {
    description = "HTTP / WebSockets"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "HTTPS / WebSockets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  ingress {
    description = "Custom Port"
    from_port   = 8080
    to_port     = 8080
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "WebSocket tunnel (home to VPS)"
    from_port   = 8765
    to_port     = 8765
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
    Name = "vps-websocket-sg"
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] 
}

resource "aws_instance" "vps" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = "t3.micro"
  vpc_security_group_ids = [aws_security_group.vps_websocket_sg.id]
  key_name               = "MyKeyPairPutty" # SSH key pair name

  user_data = <<-EOF
                #!/bin/bash
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -y
                apt-get upgrade -y
                apt-get install -y python3 python3-pip
                pip3 install websockets
                
                mkdir -p /home/ubuntu/websocket-proxy

                cat << 'PYTHONEOF' > /home/ubuntu/websocket-proxy/vps.py
                ${file("../vps.py")}
                PYTHONEOF

                chown -R ubuntu:ubuntu /home/ubuntu/websocket-proxy

                nohup python3 /home/ubuntu/websocket-proxy/vps.py > /home/ubuntu/websocket-proxy/app.log 2>&1 &
                EOF

  tags = {
    Name = "WebSocket-ReverseProxy-VPS"
  }
}

output "vps_public_ip" {
  value       = aws_instance.vps.public_ip
  description = "Public VPS IP address"
}