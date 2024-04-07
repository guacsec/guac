{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    colima
    docker
    docker-compose
    jq  
    gcc
    go_1_21
    golangci-lint
    gopls
    gotests
    goreleaser
    nats-server
    protobuf
    protoc-gen-go
    protoc-gen-go-grpc
  ];
}
