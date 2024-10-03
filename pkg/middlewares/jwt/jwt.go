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
	"github.com/traefik/traefik/v3/pkg/config/dynamic"
	"github.com/traefik/traefik/v3/pkg/middlewares"
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
	logger := middlewares.GetLogger(ctx, name, typeName)
	logger.Debug().Msg("Creating JWT middleware")

	if redisClient == nil {
		logger.Debug().Msg("JWT: Creating RedisClient")

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
	ctx := req.Context()
	logger := middlewares.GetLogger(ctx, jwt.name, typeName)

	token := req.Header.Get("Authorization")
	if token != "" && strings.Contains(token, "JWT ") {
		count, err := jwt.redisClient.Exists(ctx, strings.Trim(token, "JWT ")).Result()
		if err != nil {
			logger.Error().Msgf("JWT: Redis error: %+v", err)
		} else if count > 0 {
			logger.Debug().Msg("JWT: Blocking jwt token")
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
