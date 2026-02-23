terraform {
  # S3 backend config is injected by workflow via:
  # terraform init -backend-config="..."
  backend "s3" {}
}
