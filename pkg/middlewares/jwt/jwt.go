// Package plugindemo a demo plugin.
package jwt

import (
	"context"
	"fmt"
	"net/http"
	"strings"

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
	logger.Debug("Creating middleware")

	if config.RedisURL == "" {
		return nil, fmt.Errorf("RedisURL not defined")
	}

	opts, err := redis.ParseURL(config.RedisURL)
	if err != nil {
		// To avoid username/password leak not passing RedisURL value in error
		return nil, fmt.Errorf("failed to prase RedisURL")
	}
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
		count, _ := jwt.redisClient.Exists(ctx, strings.Trim(token, "JWT ")).Result()
		if count > 0 {
			logger.Debug("Blocking jwt token")
			http.Error(res, "Expired token", http.StatusUnauthorized)
			return
		}
	}
	jwt.next.ServeHTTP(res, req)
}
