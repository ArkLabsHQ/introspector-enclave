{
  description = "Introspector Nitro Enclave - reproducible build";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachSystem [ "x86_64-linux" ] (system:
      let
        pkgs = import nixpkgs { inherit system; };

        # Pass VERSION and AWS_REGION via environment when building:
        #   VERSION=dev AWS_REGION=us-east-1 nix build --impure .#enclave-image
        version = let v = builtins.getEnv "VERSION"; in if v == "" then "dev" else v;
        region = let r = builtins.getEnv "AWS_REGION"; in if r == "" then "us-east-1" else r;

        # Filter source to only include files relevant to the Go build.
        src = pkgs.lib.cleanSourceWith {
          src = ./.;
          filter = path: type:
            let
              relPath = pkgs.lib.removePrefix (toString ./. + "/") (toString path);
              isGoFile = pkgs.lib.hasSuffix ".go" path;
              isGoMod = builtins.baseNameOf path == "go.mod" || builtins.baseNameOf path == "go.sum";
              isInternal = pkgs.lib.hasPrefix "internal/" relPath;
            in
              type == "directory" || isGoFile || isGoMod || isInternal;
        };

        # Main application binary.
        introspector = pkgs.buildGoModule {
          pname = "introspector-skeleton";
          inherit version src;

          vendorHash = "sha256-u96n5gzvEdtVy8h78XgnU2vGjexdsJC4j+MKD7FblJw=";

          subPackages = [ "." ];
          env.CGO_ENABLED = "0";
          ldflags = [ "-X" "main.Version=${version}" ];

          # Deterministic build flags matching the original Dockerfile.
          buildFlags = [ "-trimpath" ];
          tags = [ "netgo" ];
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
          doCheck = false; # tests require network access

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
          cp ${introspector}/bin/introspector $out/app/introspector-skeleton
          cp ${nitriding}/bin/nitriding $out/app/nitriding
          cp ${viproxy}/bin/proxy $out/app/proxy
          install -m 0755 ${./enclave/start.sh} $out/app/start.sh
        '';

        # Docker image for nitro-cli build-enclave.
        # dockerTools.buildImage produces a deterministic, single-layer image.
        enclave-image = pkgs.dockerTools.buildImage {
          name = "introspector-enclave";
          tag = "nix";
          created = "2024-01-01T00:00:00Z";

          copyToRoot = pkgs.buildEnv {
            name = "enclave-root";
            paths = [
              appDir
              pkgs.busybox    # provides /bin/sh and basic utils
              pkgs.cacert     # TLS CA certificates
            ];
            pathsToLink = [ "/" ];
          };

          config = {
            Entrypoint = [ "/app/start.sh" ];
            WorkingDir = "/app";
            Env = [
              "PATH=/app:/bin:/usr/bin"
              "INTROSPECTOR_DATADIR=/app/data"
              "INTROSPECTOR_DEPLOYMENT=${version}"
              "INTROSPECTOR_AWS_REGION=${region}"
              "SSL_CERT_FILE=/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };

      in
      {
        packages = {
          inherit introspector nitriding viproxy enclave-image;
          default = enclave-image;
        };
      }
    );
}
