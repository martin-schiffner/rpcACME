package models

import (
	"crypto/tls"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

type RpcInstance struct {
	Client *grpc.ClientConn
}

func ConnectRpc(grpcServerUri string) (RpcInstance, error) {
	creds := credentials.NewTLS(&tls.Config{InsecureSkipVerify: true})

	conn, err := grpc.NewClient(grpcServerUri, grpc.WithTransportCredentials(creds))

	if err != nil {
		return RpcInstance{}, err
	}

	rpcConn := RpcInstance{
		Client: conn,
	}

	return rpcConn, nil
}
