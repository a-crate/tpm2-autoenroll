# What `check-config` promises nix/module.nix.
#
# The module's volume submodule is freeform, so Nix cannot tell a key the daemon
# knows from one it does not; the build instead runs the daemon over the file it
# generated. That is only worth anything if a bad config really does exit
# non-zero, which is what this asserts. No VM: the subcommand touches no device,
# no TPM and no socket, so it answers the same in a sandbox as on the target.
{
  lib,
  runCommand,
  writeText,
  tpm2-autoenrolld,
}:

let
  json = name: value: writeText name (builtins.toJSON value);

  good = json "good.json" {
    volumes.root = {
      device = "/dev/vda2";
      pcrs = [ 7 ];
      tpm2_device = "auto";
      pcr_bank = "sha256";
    };
  };

  bad = {
    # The case the freeform submodule makes possible: a plausible key that Nix
    # passed straight through and the daemon does not know.
    unknown-key = {
      volumes.root = {
        device = "/dev/vda2";
        pcrs = [ 7 ];
        pcr_banks = "sha256";
      };
    };
    # A policy over no PCRs unseals unconditionally.
    empty-pcrs = {
      volumes.root = {
        device = "/dev/vda2";
        pcrs = [ ];
      };
    };
    not-a-pcr = {
      volumes.root = {
        device = "/dev/vda2";
        pcrs = [ 24 ];
      };
    };
    relative-device = {
      volumes.root = {
        device = "vda2";
        pcrs = [ 7 ];
      };
    };
    # Nothing to serve at all, which from a generated file means a mistake.
    no-volumes = {
      volumes = { };
    };
  };

  badFiles = lib.mapAttrsToList (name: value: json "${name}.json" value) bad;
in
runCommand "tpm2-autoenroll-config-check" { } ''
  exe=${lib.getExe tpm2-autoenrolld}

  if ! $exe check-config --config=${good}; then
    echo "check-config rejected a valid config, expected it to pass" >&2
    exit 1
  fi

  for file in ${lib.concatStringsSep " " badFiles}; do
    if $exe check-config --config=$file; then
      echo "check-config accepted $file, expected a non-zero exit" >&2
      exit 1
    fi
  done

  touch $out
''
