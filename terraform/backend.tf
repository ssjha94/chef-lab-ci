# WARNING: Local backend - state is lost after each GH Actions run.
# Each run creates NEW instances with no way to auto-destroy them.
# Remember to manually terminate instances in the AWS console,
# or switch to S3 backend below.

terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# Uncomment for remote state (S3 backend) - recommended for production:
# terraform {
#   backend "s3" {
#     bucket         = "your-terraform-state-bucket"
#     key            = "chef-bootstrap/terraform.tfstate"
#     region         = "ap-northeast-3"
#     encrypt        = true
#     dynamodb_table = "terraform-locks"
#   }
# }
