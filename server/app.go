package server

import (
	"log/slog"
	"os"
	"rpcca/acme/certservice"
	"rpcca/acme/config"
	"rpcca/acme/controllers"
	"rpcca/acme/models"
	"rpcca/acme/worker"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/limiter"
	"github.com/gofiber/fiber/v3/middleware/logger"
)

func setupMiddleware(app *fiber.App) {
	app.Use(logger.New())

	// rate limiting
	app.Use(limiter.New(limiter.Config{
		Max:        50,
		Expiration: 10 * time.Second,
	}))
}

func InitApp(mi *models.MongoInstance, rpc *models.RpcInstance, cfg *config.Config) (*fiber.App, error) {
	certificateRepo := certservice.NewCertificateRepository(mi, rpc)
	acmeRepo := models.NewAcmeRepository(mi)

	// initialize default l (separate to the Fiber one)
	l := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level:     slog.LevelDebug,
		AddSource: true,
	}))

	certsService := certservice.NewCertService(certificateRepo, l)
	cryptoService := controllers.NewCryptoService(*cfg)
	acmeService := controllers.NewAcmeService(acmeRepo, cryptoService)

	// background worker
	jobQueue := make(chan worker.Job, worker.MAX_QUEUE)
	dispatcher := worker.NewDispatcher(worker.MAX_WORKER, jobQueue, mi, certsService, l)
	dispatcher.Run()

	app := fiber.New(fiber.Config{
		BodyLimit:    4 * 512 * 512,
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	})

	setupMiddleware(app)

	// ACME stuff
	controllers.NewAcmeController(app.Group("/acme"), certsService, acmeService, cryptoService, *cfg, dispatcher)

	return app, nil
}
