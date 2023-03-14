{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    colima
    docker
    docker-compose  
    gcc
    go_1_19
    gopls
    gotests
    protobuf
  ];
}
