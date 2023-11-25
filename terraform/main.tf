locals {
  base_tags = {
    Service = "logseq_sync"
  }
}

data "aws_caller_identity" "current" {}

locals {
  owner_arn = data.aws_caller_identity.current.arn
}

data "aws_iam_policy_document" "assume_role" {
  statement {
    sid     = "IssueTempCredentials"
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "AWS"
      identifiers = [local.owner_arn]
    }
  }
}

data "aws_iam_policy_document" "logseq" {
  statement {
    sid     = "AllowS3Access"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.default.arn,
      "${aws_s3_bucket.default.arn}/*",
    ]
  }
}

resource "aws_iam_policy" "logseq" {
  name   = "logseq_s3_policy"
  path   = "/"
  policy = data.aws_iam_policy_document.logseq.json
}

resource "aws_iam_role" "sync" {
  name = "logseq_sync"

  assume_role_policy = data.aws_iam_policy_document.assume_role.json

  tags = merge(local.base_tags, {
    Name = "Temp Credential Role"
  })
}

resource "aws_iam_role_policy_attachment" "logseq_bucket_access" {
  role       = aws_iam_role.sync.name
  policy_arn = aws_iam_policy.logseq.arn
}

resource "aws_s3_bucket" "default" {
  bucket_prefix = "logseq-sync-"

  tags = merge(local.base_tags, {
    Name = "Logseq Sync Blob Storage"
  })
}

data "aws_iam_policy_document" "s3_access" {
  statement {
    sid     = "AllowS3Access"
    effect  = "Allow"
    actions = ["s3:*"]
    resources = [
      aws_s3_bucket.default.arn,
      "${aws_s3_bucket.default.arn}/*",
    ]

    principals {
      type = "AWS"
      identifiers = [
        local.owner_arn,
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "default" {
  bucket = aws_s3_bucket.default.id
  policy = data.aws_iam_policy_document.s3_access.json
}

resource "aws_s3_bucket_public_access_block" "default" {
  bucket = aws_s3_bucket.default.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

  depends_on = [aws_s3_bucket_policy.default]
}
