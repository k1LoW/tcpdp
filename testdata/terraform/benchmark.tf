provider "aws" {
  region = "ap-northeast-1"
}

resource "aws_vpc" "default" {
  cidr_block = "10.0.0.0/16"
  enable_dns_hostnames = true
  tags {
    Name = "vpc_tcpdp"
  }
}

resource "aws_internet_gateway" "igw" {
    vpc_id = "${aws_vpc.default.id}"
    tags {
        Name = "igw_tcpdp"
    }
}

resource "aws_subnet" "public_b" {
  vpc_id            = "${aws_vpc.default.id}"
  cidr_block        = "10.0.1.0/24"
  availability_zone = "ap-northeast-1b"

  tags {
    Name = "subnet_tcpdp_public_a"
  }
}

resource "aws_subnet" "public_c" {
  vpc_id            = "${aws_vpc.default.id}"
  cidr_block        = "10.0.2.0/24"
  availability_zone = "ap-northeast-1c"

  tags {
    Name = "subnet_tcpdp_public_c"
  }
}

resource "aws_subnet" "private_b" {
  vpc_id            = "${aws_vpc.default.id}"
  cidr_block        = "10.0.3.0/24"
  availability_zone = "ap-northeast-1b"

  tags {
    Name = "subnet_tcpdp_private_a"
  }
}

resource "aws_subnet" "private_c" {
  vpc_id            = "${aws_vpc.default.id}"
  cidr_block        = "10.0.4.0/24"
  availability_zone = "ap-northeast-1c"

  tags {
    Name = "subnet_tcpdp_private_c"
  }
}

resource "aws_route_table" "public-rt" {
    vpc_id = "${aws_vpc.default.id}"
    route {
        cidr_block = "0.0.0.0/0"
        gateway_id = "${aws_internet_gateway.igw.id}"
    }
    tags {
        Name = "public-rt"
    }
}

resource "aws_route_table_association" "rta-1b" {
    subnet_id = "${aws_subnet.public_b.id}"
    route_table_id = "${aws_route_table.public-rt.id}"
}

resource "aws_route_table_association" "rta-1c" {
    subnet_id = "${aws_subnet.public_c.id}"
    route_table_id = "${aws_route_table.public-rt.id}"
}

resource "aws_security_group" "ec2" {
  name = "sg_ec2_tcpdp"
  vpc_id = "${aws_vpc.default.id}"

  ingress {
    from_port = 22
    to_port = 22
    protocol = "tcp"
    description = "SSH"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name = "sg_ec2_tcpdp"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_security_group" "rds" {
  name = "sg_rds_tcpdp"
  vpc_id = "${aws_vpc.default.id}"

  ingress {
    from_port = 3306
    to_port = 3306
    protocol = "tcp"
    description = "tcpdp"
    security_groups = ["${aws_security_group.ec2.id}"]
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port = 0
    to_port = 0
    protocol = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags {
    Name = "sg_rds_tcpdp"
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_key_pair" "default" {
  key_name   = "key_tcpdp"
  public_key = "${file("~/.ssh/id_rsa.pub")}"
}

resource "aws_instance" "default" {
  ami = "ami-e99f4896" // Amazon Linux 2 AMI (HVM), SSD Volume Type
  instance_type = "m4.large"
  associate_public_ip_address = "true"
  key_name                    = "${aws_key_pair.default.key_name}"
  subnet_id                   = "${aws_subnet.public_b.id}"
  vpc_security_group_ids      = ["${aws_security_group.ec2.id}"]

  root_block_device {
    volume_type = "standard"
    volume_size = "50"
    delete_on_termination = "false"
  }

  tags {
    "Name" = "tcpdp"
  }
}

resource "aws_db_subnet_group" "default" {
  name = "db_subnet_group_tcpdp"
  subnet_ids = ["${aws_subnet.private_b.id}", "${aws_subnet.private_c.id}"]

  tags {
    Name = "db_subnet_group_tcpdp"
  }
}

resource "aws_db_parameter_group" "default" {
  name   = "pgtcpdp"
  family = "mysql5.7"

  parameter {
    name  = "max_connect_errors"
    value = "1000"
  }
}

resource "aws_db_instance" "tcpdp" {
  allocated_storage    = 10
  storage_type         = "gp2"
  engine               = "mysql"
  engine_version       = "5.7.22"
  instance_class       = "db.m4.large"
  name                 = "tcpdp"
  username             = "tcpdp"
  password             = "tcpdppass"
  parameter_group_name = "${aws_db_parameter_group.default.id}"
  apply_immediately    = true
  skip_final_snapshot = true
  vpc_security_group_ids = ["${aws_security_group.rds.id}"]
  db_subnet_group_name = "${aws_db_subnet_group.default.id}"
  publicly_accessible = true
}
