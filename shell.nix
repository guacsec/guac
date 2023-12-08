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
    gopls
    gotests
    goreleaser
    nats-server
    protobuf
  ];
}
