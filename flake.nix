{
  inputs = {
    nixpkgs.url = "nixpkgs";
    utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nix-community/naersk";
    flake-compat = {
      url = "github:edolstra/flake-compat";
      flake = false;
    };
  };

  outputs = { self, nixpkgs, utils, naersk, ... }:
    utils.lib.eachDefaultSystem (system:
      let
        pkgs = import nixpkgs { inherit system; };
        naersk-lib = naersk.lib."${system}";
      in
      rec {
        # `nix build`
        packages.cargo-bpf = naersk-lib.buildPackage {
          meta = with pkgs.lib; {
            description = "Rust eBPF tooling";
            homepage = "https://foniod.org";
            license = licenses.mit;
            platforms = [ "x86_64-linux" "aarch64-linux" ];
          };

          name = "cargo-bpf";
          version = "3.0.0";

          src = ./.;
          root = ./.;
          gitSubmodules = true;

          LIBCLANG_PATH = "${pkgs.llvmPackages_14.libclang.lib}/lib";
          KERNEL_SOURCE = "${pkgs.linuxPackages.kernel.dev}/lib/modules/${pkgs.linuxPackages.kernel.version}";

          nativeBuildInputs = with pkgs; [
            pkgconfig
            llvm_14
            clang_14
          ];
          buildInputs = with pkgs; [
            openssl
            zlib
            libxml2
            libelf
            llvm_13.dev
            clang_13
            linuxPackages.kernel.dev
            linuxHeaders
            glibc.dev
          ];
        };
        defaultPackage = packages.cargo-bpf;

        defaultApp = apps.cargo-bpf;
        apps.cargo-bpf = {
          type = "app";
          program = "${self.defaultPackage."${system}"}/bin/cargo-bpf";
        };

        # `nix develop`
        devShell = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.cargo-bpf ];
          nativeBuildInputs = with pkgs; [
            cargo
            pkg-config
            rustc
            rust-analyzer
            rustfmt
            clippy
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages_14.libclang.lib}/lib";
        };
      });
}
