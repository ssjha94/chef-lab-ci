terraform {
  backend "local" {
    path = "terraform.tfstate"
  }
}

# Uncomment for remote state (S3 backend)
# terraform {
#   backend "s3" {
#     bucket         = "your-terraform-state-bucket"
#     key            = "chef-nodes/terraform.tfstate"
#     region         = "ap-northeast-3"
#     encrypt        = true
#     dynamodb_table = "terraform-locks"
#   }
# }
