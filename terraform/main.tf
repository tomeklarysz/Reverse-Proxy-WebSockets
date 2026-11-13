terraform {
  required_version = ">= 1.4" 

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

variable "ssh_private_key_path" {
  type    = string
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
  ami                         = data.aws_ami.ubuntu.id
  instance_type               = "t3.micro"
  vpc_security_group_ids      = [aws_security_group.vps_websocket_sg.id]
  key_name                    = "MyKeyPairPutty" # SSH key pair name
  user_data_replace_on_change = true             

  user_data = <<-EOF
                #!/bin/bash
                export DEBIAN_FRONTEND=noninteractive
                apt-get update -y
                apt-get upgrade -y
                apt-get install -y python3 python3-pip nginx
                pip3 install websockets

                mkdir -p /etc/nginx/certs
                mkdir -p /home/ubuntu/websocket-proxy

                # Bootstrap temporary certificate so Nginx starts cleanly before sign-server.sh is run
                if [ ! -f /etc/nginx/certs/server.crt ]; then
                    openssl req -x509 -newkey rsa:2048 -nodes -keyout /etc/nginx/certs/server.key -out /etc/nginx/certs/server.crt -days 1 -subj "/CN=temporary"
                    touch /etc/nginx/certs/ca.crt
                    chmod 600 /etc/nginx/certs/server.key
                fi

                cat << 'NGINXEOF' > /etc/nginx/sites-available/default
                ${file("../nginx/default.conf")}
                NGINXEOF

                nginx -t && systemctl restart nginx

                cat << 'PYTHONEOF' > /home/ubuntu/websocket-proxy/vps.py
                ${file("../vps.py")}
                PYTHONEOF

                cat << 'SERVICEEOF' > /etc/systemd/system/tunnel-broker.service
                [Unit]
                Description=WebSocket Reverse Proxy Broker
                After=network.target

                [Service]
                Type=simple
                User=ubuntu
                WorkingDirectory=/home/ubuntu/websocket-proxy
                ExecStart=/usr/bin/python3 /home/ubuntu/websocket-proxy/vps.py --host 127.0.0.1 --http-port 8080 --ws-port 8765
                Restart=always
                RestartSec=3

                [Install]
                WantedBy=multi-user.target
                SERVICEEOF

                chown -R ubuntu:ubuntu /home/ubuntu/websocket-proxy
                systemctl daemon-reload
                systemctl enable tunnel-broker
                systemctl start tunnel-broker
                EOF

  tags = {
    Name = "WebSocket-ReverseProxy-VPS"
  }
}

resource "terraform_data" "server_cert" {
  triggers_replace = [aws_instance.vps.id]

  connection {
    type        = "ssh"
    host        = aws_instance.vps.public_ip
    user        = "ubuntu"
    private_key = file(pathexpand(var.ssh_private_key_path))
    timeout     = "5m"
  }

  provisioner "remote-exec" {
    inline = ["cloud-init status --wait || true"]
  }

  provisioner "local-exec" {
    working_dir = "${path.module}/.."
    interpreter = ["PowerShell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"]
    command     = "& .\\sign-server.ps1 '${aws_instance.vps.public_ip}' '${pathexpand(var.ssh_private_key_path)}'; exit $LASTEXITCODE"
  }
}

output "vps_public_ip" {
  value       = aws_instance.vps.public_ip
  description = "Public VPS IP address"
}
