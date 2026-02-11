{
  description = "Introspector Nitro Enclave - reproducible build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    aws-nitro-util.url = "github:monzo/aws-nitro-util";
  };

  outputs = { self, nixpkgs, flake-utils, aws-nitro-util }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };
        nitro = aws-nitro-util.lib.${system};

        # Pass build-time variables via environment when building:
        #   VERSION=dev AWS_REGION=us-east-1 CDK_PREFIX=dev nix build --impure .#eif
        version = let v = builtins.getEnv "VERSION"; in if v == "" then "dev" else v;
        region = let r = builtins.getEnv "AWS_REGION"; in if r == "" then "us-east-1" else r;
        deployment = let d = builtins.getEnv "CDK_PREFIX"; in if d == "" then "dev" else d;

        # Filter source to only include files relevant to the Go build.
        src = pkgs.lib.cleanSourceWith {
          src = ../enclave;
          filter = path: type:
            let
              isGoFile = pkgs.lib.hasSuffix ".go" path;
              isGoMod = builtins.baseNameOf path == "go.mod" || builtins.baseNameOf path == "go.sum";
            in
              type == "directory" || isGoFile || isGoMod;
        };

        # Init binary: decrypts key via KMS, extends PCR16 with pubkey hash,
        # then exec's the real introspector binary.
        introspector-init = pkgs.buildGoModule {
          pname = "introspector-init";
          inherit version src;

          vendorHash = "sha256-Su+49otxVLeqvSNCn0SFRpT1tASt5iwklEz29CyxCqE=";

          subPackages = [ "." ];
          env.CGO_ENABLED = "0";
          ldflags = [
            "-X" "main.Version=${version}"
          ];

          # Deterministic build flags.
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];

          postInstall = ''
            mv $out/bin/introspector-enclave $out/bin/introspector-init
          '';
        };

        # Upstream introspector binary (full signing service).
        # Built from ArkLabsHQ/introspector source at a pinned commit.
        introspector-upstream = pkgs.buildGoModule {
          pname = "introspector";
          version = "unstable-2026-01-29";

          src = pkgs.fetchFromGitHub {
            owner = "ArkLabsHQ";
            repo = "introspector";
            rev = "dcec46c447261a0dc7895cae7771283fafc803d2";
            hash = "sha256-3Ce/GX4O2Mg0PH82ESGx7MMYJw+mYZnnrIkdCHTVluI=";
          };

          vendorHash = "sha256-Zk7onQE+KLrctHt4H5NBfxorySkl+dzkPOhRRky8yI4=";

          subPackages = [ "cmd" ];
          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/cmd $out/bin/introspector
          '';
        };

        # Nitriding TLS termination daemon.
        nitriding = pkgs.buildGoModule {
          pname = "nitriding-daemon";
          version = "unstable-2024-01-01";

          src = pkgs.fetchFromGitHub {
            owner = "brave";
            repo = "nitriding-daemon";
            rev = "c8cb7248843c82a5d72ff6cdde90f4a4cf68c87f";
            hash = "sha256-0ww8ZcoUh3UgRJyhfEVwmjxk3tZv7exCw0VmftdnM7U=";
          };

          vendorHash = "sha256-B/1tbPfId6qgvaMwPF5w4gFkkkeoI+5k+x0jEvJxQus=";

          env.CGO_ENABLED = "0";
          buildFlags = [ "-trimpath" ];
          doCheck = false;

          postInstall = ''
            mv $out/bin/nitriding-daemon $out/bin/nitriding
          '';
        };

        # Viproxy for IMDS forwarding inside the enclave.
        viproxy = pkgs.buildGoModule {
          pname = "viproxy";
          version = "0.1.2";

          src = pkgs.fetchFromGitHub {
            owner = "brave";
            repo = "viproxy";
            rev = "v0.1.2";
            hash = "sha256-xcQCvl+/d7a3fdqDMEEIyP3c49l1bu7ptCG+RZ94Xws=";
          };

          vendorHash = "sha256-WOzeqHo1cG8USbGUm3OAEUgh3yKTamCaIL3FpsshnjI=";

          subPackages = [ "example" ];
          env.CGO_ENABLED = "0";

          postInstall = ''
            mv $out/bin/example $out/bin/proxy
          '';
        };

        # Assemble the /app directory with all binaries and scripts.
        appDir = pkgs.runCommand "enclave-app" { } ''
          mkdir -p $out/app/data
          cp ${introspector-init}/bin/introspector-init $out/app/introspector-init
          cp ${introspector-upstream}/bin/introspector $out/app/introspector
          cp ${nitriding}/bin/nitriding $out/app/nitriding
          cp ${viproxy}/bin/proxy $out/app/proxy
          install -m 0755 ${../enclave/start.sh} $out/app/start.sh
        '';

        # Complete rootfs for the enclave.
        enclaveRootfs = pkgs.buildEnv {
          name = "enclave-rootfs";
          paths = [
            appDir
            pkgs.busybox    # provides /bin/sh and basic utils
            pkgs.cacert     # TLS CA certificates
          ];
          pathsToLink = [ "/" ];
        };

        # Environment variables for the enclave.
        enclaveEnv = ''
          PATH=/app:/bin:/usr/bin
          INTROSPECTOR_DATADIR=/app/data
          INTROSPECTOR_DEPLOYMENT=${deployment}
          INTROSPECTOR_AWS_REGION=${region}
          AWS_REGION=${region}
          SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt
        '';

        # Build EIF using monzo/aws-nitro-util (reproducible, no Docker).
        eif = nitro.buildEif {
          name = "introspector-enclave";
          inherit version;

          arch = "x86_64";
          kernel = nitro.blobs.x86_64.kernel;
          kernelConfig = nitro.blobs.x86_64.kernelConfig;
          nsmKo = nitro.blobs.x86_64.nsmKo;

          copyToRoot = enclaveRootfs;
          entrypoint = "/app/start.sh";
          env = enclaveEnv;
        };

      in
      {
        packages = {
          inherit introspector-init introspector-upstream nitriding viproxy eif;
          default = eif;
        };
      }
    );
}
