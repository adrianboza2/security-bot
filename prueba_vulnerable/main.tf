resource "aws_s3_bucket" "public_logs" {
  bucket = "demo-public-logs"
}

resource "aws_s3_bucket_acl" "public_logs_acl" {
  bucket = aws_s3_bucket.public_logs.id
  acl    = "public-read"
}

resource "aws_security_group" "public_ssh" {
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}