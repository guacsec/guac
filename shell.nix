{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    gcc
    go_1_19
    gopls
    gotests
  ];
}
