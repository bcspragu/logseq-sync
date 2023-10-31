// Package awsblob provides the blob operations needed by Logseq Sync, backed by AWS's S3.
package awsblob

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials/stscreds"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/bcspragu/logseq-sync/blob"
)

type Client struct {
	sess *session.Session
	// iam  *iam.IAM
	// sts  *sts.STS

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
		// iam:  iamSvc,
		// sts:  stsSvc,
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
