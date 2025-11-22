package main

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"path"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

type Storage struct {
	client      *s3.Client
	bucket      string
	publicBase  string
	rawEndpoint string
}

func NewStorage(ctx context.Context, cfg Config) (*Storage, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion("auto"),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(cfg.AccessKeyID, cfg.SecretAccessKey, "")),
	)
	if err != nil {
		return nil, fmt.Errorf("load aws config: %w", err)
	}

	client := s3.NewFromConfig(awsCfg, func(o *s3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(cfg.Endpoint)
	})

	return &Storage{
		client:      client,
		bucket:      cfg.Bucket,
		publicBase:  cfg.PublicBaseURL,
		rawEndpoint: cfg.Endpoint,
	}, nil
}

func (s *Storage) Upload(ctx context.Context, key string, contentType string, body io.Reader, size int64) (string, error) {
	_, err := s.client.PutObject(ctx, &s3.PutObjectInput{
		Bucket:      aws.String(s.bucket),
		Key:         aws.String(key),
		Body:        body,
		ContentType: aws.String(contentType),
	})
	if err != nil {
		return "", fmt.Errorf("put object: %w", err)
	}

	return s.objectURL(key), nil
}

func (s *Storage) objectURL(key string) string {
	if s.publicBase != "" {
		return strings.TrimSuffix(s.publicBase, "/") + "/" + key
	}

	u, err := url.Parse(s.rawEndpoint)
	if err != nil {
		return ""
	}
	u.Path = path.Join(u.Path, s.bucket, key)
	return u.String()
}
