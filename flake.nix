{
  description = "openlv devshell";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = {
    self,
    nixpkgs,
    flake-utils,
    rust-overlay,
  }:
    flake-utils.lib.eachDefaultSystem (system: let
      pkgs = import nixpkgs {
        inherit system;
        overlays = [rust-overlay.overlays.default];
      };

      rustToolchain = pkgs.rust-bin.stable.latest.default.override {
        extensions = [
          "rust-src"
          "llvm-tools"
        ];
        targets = ["wasm32-unknown-unknown"];
      };

      rustfmtNightly = pkgs.rust-bin.nightly.latest.rustfmt;
    in {
      devShells = {
        default = pkgs.mkShell {
          packages = with pkgs; [
            rustfmtNightly
            rustToolchain
            rust-analyzer
            # rustfmt
            # clippy
            # cargo
            # rustc
            bacon

            just
            nodejs_24
            pnpm_11
            chromium
          ];

          shellHook = ''
            # Playwright's downloaded browsers miss NixOS shared libs; use nixpkgs chromium.
            export PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD=1
            export PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH="${pkgs.chromium}/bin/chromium"

            just
          '';
        };
      };
    });
}
