// Package plugindemo a demo plugin.
package jwt

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-redis/redis/v8"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/log"
	"github.com/traefik/traefik/v2/pkg/middlewares"
)

const (
	typeName = "Jwt"
)

// JWT a JWT plugin.
type JWT struct {
	next        http.Handler
	name        string
	redisClient *redis.Client
}

func New(ctx context.Context, next http.Handler, config dynamic.Jwt, name string) (http.Handler, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))
	logger.Debug("Creating JWT middleware")

	if config.RedisURL == "" {
		return nil, fmt.Errorf("RedisURL not defined")
	}

	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		// To avoid username/password leak not passing RedisURL value in error
		return nil, fmt.Errorf("failed to prase RedisURL")
	}

	if config.RedisDialTimeout != 0 {
		// Converting RedisDialTimeout to time.Duration
		opts.DialTimeout = time.Duration(config.RedisDialTimeout) * time.Second
	}

	// setting MaxRetries as -1 disables retry.
	if config.RedisMaxRetry != 0 {
		opts.MaxRetries = config.RedisMaxRetry
	}

	// Enable TLS and Set redis password
	opts.TLSConfig = &tls.Config{}

	return &JWT{
		next:        next,
		name:        name,
		redisClient: redis.NewClient(opts),
	}, nil
}

func (jwt *JWT) ServeHTTP(res http.ResponseWriter, req *http.Request) {
	ctx := middlewares.GetLoggerCtx(req.Context(), jwt.name, typeName)
	logger := log.FromContext(ctx)

	token := req.Header.Get("Authorization")
	if token != "" && strings.Contains(token, "JWT ") {
		count, err := jwt.redisClient.Exists(ctx, strings.Trim(token, "JWT ")).Result()
		if err != nil {
			logger.Errorf("JWT: Redis error: %+v", err)
		} else if count > 0 {
			logger.Debug("JWT: Blocking jwt token")
			http.Error(res, "Expired JWT token", http.StatusUnauthorized)
			return
		}
	}
	jwt.next.ServeHTTP(res, req)
}
