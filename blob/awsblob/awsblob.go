// Package awsblob provides the blob operations needed by Logseq Sync, backed by AWS's S3.
package awsblob

import (
	"context"
	"errors"
	"fmt"
	"path"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/bcspragu/logseq-sync/blob"
)

type Client struct {
	sess *session.Session
	// iam  *iam.IAM
	// sts  *sts.STS
	s3 *s3.S3

	bkt     string
	roleARN string
}

func New(bkt, roleARN string) (*Client, error) {
	sess, err := session.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to authenticate with AWS: %w", err)
	}

	// iamSvc := iam.New(sess)
	// stsSvc := sts.New(sess)

	return &Client{
		bkt:     bkt,
		roleARN: roleARN,

		sess: sess,
		s3:   s3.New(sess),
		// iam:  iamSvc,
		// sts:  stsSvc,
	}, nil
}

func (c *Client) Bucket() string {
	return c.bkt
}

// S3 doesn't have a 'move' operation, so we just do copy and delete. See
// https://stackoverflow.com/q/63061426
func (c *Client) Move(ctx context.Context, srcPath, destPath string) (*blob.MoveMeta, error) {
	src, dest := path.Join(c.bkt, srcPath), path.Join(c.bkt, destPath)
	attrResp, err := c.s3.GetObjectAttributes(&s3.GetObjectAttributesInput{
		Bucket: aws.String(c.bkt),
		Key:    aws.String(src),
		ObjectAttributes: []*string{
			aws.String("Checksum"),
			aws.String("ObjectSize"),
		},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get attributes for %q: %w", src, err)
	}
	if attrResp.LastModified == nil {
		return nil, errors.New("last_modified wasn't populated in GetObjectAttributes")
	}
	if attrResp.ObjectSize == nil {
		return nil, errors.New("object_size wasn't populated in GetObjectAttributes")
	}

	if _, err := c.s3.CopyObject(&s3.CopyObjectInput{
		Bucket:     aws.String(c.bkt),
		CopySource: aws.String(src),
		Key:        aws.String(dest),
	}); err != nil {
		return nil, fmt.Errorf("failed to copy file %q to %q: %w", src, dest, err)
	}

	if _, err := c.s3.DeleteObject(&s3.DeleteObjectInput{
		Bucket: aws.String(c.bkt),
		Key:    aws.String(src),
	}); err != nil {
		return nil, fmt.Errorf("failed to delete source file %q after copying: %w", src, err)
	}

	return &blob.MoveMeta{
		LastModified: *attrResp.LastModified,
		Size:         *attrResp.ObjectSize,
	}, nil
}

func (c *Client) GenerateTempCreds(ctx context.Context, prefix string) (*blob.Credentials, error) {
	// c.iam.PutRolePolicy(&iam.PutRolePolicyInput{
	// 	PolicyDocument: aws.String(fmt.Sprintf(`
	//    {
	//      "Version": "2012-10-17",
	//      "Statement": [
	//        {
	//          "Effect": "Allow",
	//          "Action": "s3:PutObject",
	//          "Resource": "arn:aws:s3:::%s/%s/*"
	//        },
	//      ]
	//    }
	// `, c.bkt, prefix)),
	// 	PolicyName: aws.String("bucket-access-" + prefix),
	// 	RoleName:   res.Role.Arn,
	// })

	creds := stscreds.NewCredentials(c.sess, c.roleARN, func(sc *stscreds.AssumeRoleProvider) {
		// TODO: Figure out what the real API uses here.
		sc.Duration = 2 * time.Minute
		sc.Policy = aws.String(fmt.Sprintf(`
    {
      "Version": "2012-10-17",
      "Statement": [
        {
          "Effect": "Allow",
          "Action": "s3:PutObject",
          "Resource": "arn:aws:s3:::%s/%s/*"
        },
      ]
    }
	`, c.bkt, prefix))
	})
	tmpCreds, err := creds.GetWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get credentials: %w", err)
	}
	exp, err := creds.ExpiresAt()
	if err != nil {
		return nil, fmt.Errorf("failed to credential expiration: %w", err)
	}

	return &blob.Credentials{
		AccessKeyID:     tmpCreds.AccessKeyID,
		SecretAccessKey: tmpCreds.SecretAccessKey,
		SessionToken:    tmpCreds.SessionToken,
		Expiration:      exp,
	}, nil
}

func (c *Client) SignedDownloadURL(ctx context.Context, key string, dur time.Duration) (string, error) {
	req, _ := c.s3.GetObjectRequest(&s3.GetObjectInput{
		Bucket: aws.String(c.bkt),
		Key:    aws.String(key),
	})
	urlStr, err := req.Presign(dur)
	if err != nil {
		return "", fmt.Errorf("failed to pre-sign S3 object: %w", err)
	}
	return urlStr, nil
}
