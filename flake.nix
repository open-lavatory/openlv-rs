{
  description = "openlv devshell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
      };
    in {
      devShells.default = pkgs.mkShell {
        packages = with pkgs; [
          just
          nodejs_24
          pnpm_11
          cargo
          clippy
          rustfmt
          rustc
          bacon
          chromium
          rust-analyzer
        ];

        shellHook = ''
          # Playwright's downloaded browsers miss NixOS shared libs; use nixpkgs chromium.
          export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
          export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="${pkgs.chromium}/bin/chromium"

          just
        '';
      };
    });
}
