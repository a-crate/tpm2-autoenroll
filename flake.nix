{
  description = "Re-bind TPM2-enrolled LUKS2 volumes to the current PCR state at the point of unlock";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs = { self, nixpkgs }:
    let
      systems = [ "x86_64-linux" "aarch64-linux" ];
      forAllSystems = f:
        nixpkgs.lib.genAttrs systems (system: f system nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (system: pkgs: rec {
        tpm2-autoenrolld = pkgs.rustPlatform.buildRustPackage {
          pname = "tpm2-autoenrolld";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;

          # Deliberately unwrapped. The daemon needs systemd-ask-password,
          # systemd-cryptenroll and cryptsetup on PATH (DESIGN.md section 9),
          # but baking them in with wrapProgram puts both packages in this
          # derivation's closure -- and the NixOS module's whole reason for
          # naming those three binaries individually in the initrd's storePaths
          # is to avoid copying a second full systemd into the initrd. A wrapper
          # would silently undo that, so the caller supplies PATH instead: the
          # module sets it per stage, which is also the only way to pick the
          # systemd that belongs to the stage being booted.

          meta = {
            description = "Re-bind TPM2-enrolled LUKS2 volumes at the point of unlock";
            mainProgram = "tpm2-autoenrolld";
            platforms = pkgs.lib.platforms.linux;
          };
        };

        default = tpm2-autoenrolld;
      });

      # No overlay: setting the option is enough, and nixpkgs.overlays from an
      # imported module fights the nixpkgs.pkgs that flake-based configurations
      # commonly set. mkDefault so a user can still substitute their own build.
      nixosModules.tpm2-autoenroll = { pkgs, lib, ... }: {
        imports = [ ./nix/module.nix ];
        services.tpm2-autoenroll.package =
          lib.mkDefault self.packages.${pkgs.stdenv.hostPlatform.system}.tpm2-autoenrolld;
      };

      nixosModules.default = self.nixosModules.tpm2-autoenroll;

      devShells = forAllSystems (system: pkgs: {
        default = pkgs.mkShell {
          packages = with pkgs; [
            cargo
            rustc
            rustfmt
            clippy
            rust-analyzer
            # For poking at the mechanism by hand outside the VM test.
            cryptsetup
            tpm2-tools
          ];
        };
      });

      checks = forAllSystems (system: pkgs:
        {
          inherit (self.packages.${system}) tpm2-autoenrolld;
        }
        # The VM test needs swtpm and a qemu the test framework knows how to
        # drive; keep it to the one platform that is actually exercised.
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          socket-core = pkgs.callPackage ./nix/vmtest.nix {
            tpm2-autoenrolld = self.packages.${system}.tpm2-autoenrolld;
          };
        });
    };
}
