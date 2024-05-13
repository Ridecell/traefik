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

// Use of Single Redis client to avoid excess memory consumption
var redisClient *redis.Client

// JWT a JWT plugin.
type JWT struct {
	next        http.Handler
	name        string
	redisClient *redis.Client
}

func New(ctx context.Context, next http.Handler, config dynamic.Jwt, name string) (http.Handler, error) {
	logger := log.FromContext(middlewares.GetLoggerCtx(ctx, name, typeName))
	logger.Debug("JWT: Creating JWT middleware")

	// Create redis client only once
	if redisClient == nil {
		logger.Debug("JWT: Creating RedisClient")

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
		redisClient = redis.NewClient(opts)
	}

	return &JWT{
		next:        next,
		name:        name,
		redisClient: redisClient,
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
			res.Header().Set("Content-Type", "application/json")

			// To avoid CORS error on browser level (Refer issue CAR-27637), we pass Access-Control-Allow-Origin header with Origin domain.
			if req.Header.Get("origin") != "" {
				res.Header().Set("Access-Control-Allow-Origin", req.Header.Get("origin"))
			}

			res.WriteHeader(http.StatusUnauthorized)
			res.Write([]byte(`{"error_msg":"expired_jwt_token"}`))
			return
		}
	}
	jwt.next.ServeHTTP(res, req)
}
