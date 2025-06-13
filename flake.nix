{
  description = "Efile: A cli tool for simple encryption of files";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };

        pname = "efile";
        version = "0.3.1";
      in {
        packages = {
          default = pkgs.buildGoModule {
            inherit pname version;
            src = ./.;
            hash = "sha256-X/LCfIWlnCrNvgAdHED83Eppz2SLS9kvFdFsOuRGSZs=";
            vendorHash = "sha256-X/LCfIWlnCrNvgAdHED83Eppz2SLS9kvFdFsOuRGSZs=";
          };
        };

        devShells = {
          default = pkgs.mkShell {
            buildInputs = [ pkgs.go pkgs.gopls pkgs.delve pkgs.gotools ];
          };
        };

        apps = {
          default = {
            type = "app";
            program = "${self.packages.${system}.default}/bin/${pname}";
          };
        };
      });
}
