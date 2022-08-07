{ pkgs ? import <nixpkgs> {} }:
with pkgs;
mkShell {
  buildInputs = [
    gcc
    go_1_18
    gopls
    gotests
  ];
}
