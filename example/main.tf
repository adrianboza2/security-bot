# Deliberately vulnerable Terraform sample for the DevSecOps reviewer demo.
# Do NOT deploy this. Used to verify the bot flags real findings on a PR.

resource "aws_s3_bucket" "logs" {
  bucket = "acme-public-logs"
}

resource "aws_s3_bucket_acl" "logs_acl" {
  bucket = aws_s3_bucket.logs.id
  acl    = "public-read"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "app" {
  engine            = "postgres"
  storage_encrypted = false
  publicly_accessible = true
}