package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"rpcca/acme/config"
	"rpcca/acme/models"
	"rpcca/acme/server"
	"syscall"
	"time"

	"github.com/gofiber/fiber/v3"
)

func getDatabaseUrl(host string, port int, user string, pw string) string {
	hostPort := fmt.Sprintf("%s:%d", host, port)

	u := &url.URL{
		Scheme: "mongodb",
		Host:   hostPort,
	}

	if len(user) > 0 && len(pw) > 0 {
		u.User = url.UserPassword(user, pw)
	}
	return u.String()
}

func main() {
	// load configuration
	cfg, err := config.GetConfig()
	if err != nil {
		log.Fatal(err)
	}

	// init database connection
	dbUrl := getDatabaseUrl(cfg.Database.Hostname, int(cfg.Database.Port), cfg.Database.Username, cfg.Database.Password)
	mi, err := models.Connect(dbUrl, cfg.Database.Database)
	if err != nil {
		log.Fatal("There was an error connecting to the database: ", err)
	}

	// check if database connection is available
	err = mi.Client.Ping(context.TODO(), nil)
	if err != nil {
		log.Fatal("There was an error pinging database: ", err)
	}

	// init gRPC connection
	rpc, err := models.ConnectRpc("dns:rpcca.home.arpa:44444")
	if err != nil {
		log.Fatal("There was an error connecting to the gRPC server: ", err)
	}

	app, err := server.InitApp(&mi, &rpc, &cfg)
	if err != nil {
		log.Fatal("There was an error initializing app: ", err)
	}

	go func() {
		// check if TLS is supposed to be used
		if cfg.HTTP.TLS.Enabled {
			log.Println("Starting server with TLS enabled")

			certKey, err := tls.LoadX509KeyPair(cfg.HTTP.TLS.CertificatePath, cfg.HTTP.TLS.KeyPath)
			if err != nil {
				log.Fatal("error loading TLS certificate or key: ", err)
			}

			tlsConfig := &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{certKey},
			}

			fiberConfig := &fiber.ListenConfig{
				TLSConfig: tlsConfig,
			}

			err = app.Listen(fmt.Sprintf("%s:%d", cfg.HTTP.ListenIP, cfg.HTTP.ListenPort), *fiberConfig)
			if err != nil {
				log.Fatal("error: ", err)
			}
			return
		}

		log.Println("Starting server with TLS disabled")
		err := app.Listen(fmt.Sprintf("%s:%d", cfg.HTTP.ListenIP, cfg.HTTP.ListenPort))
		if err != nil {
			log.Fatal("error:", err)
		}
	}()

	defer func() {
		err := models.Disconnect(mi)
		if err != nil {
			log.Fatal("There was an error disconnecting from database: ", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)

	<-quit

	log.Println("Received quit signal")

	log.Println("Shutting down server, waiting max. 20 secs for closing connections...")
	_ = app.ShutdownWithTimeout(time.Second * 20)

	// potential clean up tasks

	log.Println("Shut down completed.")
}
