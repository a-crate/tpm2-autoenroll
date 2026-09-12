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

          # The daemon shells out to systemd-ask-password for the prompt and to
          # cryptsetup to check a passphrase against the volume, so both must be
          # on PATH. The NixOS module will set it explicitly; this keeps the
          # package usable on its own.
          nativeBuildInputs = [ pkgs.makeWrapper ];
          postInstall = ''
            wrapProgram $out/bin/tpm2-autoenrolld \
              --prefix PATH : ${pkgs.lib.makeBinPath [ pkgs.systemd pkgs.cryptsetup ]}
          '';

          meta = {
            description = "Re-bind TPM2-enrolled LUKS2 volumes at the point of unlock";
            mainProgram = "tpm2-autoenrolld";
            platforms = pkgs.lib.platforms.linux;
          };
        };

        default = tpm2-autoenrolld;
      });

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
