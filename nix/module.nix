# The NixOS module.
#
# Each volume is listed explicitly, with the PCR selection it is to be enrolled
# against. That list is the daemon's only source of policy: the same fields in
# the LUKS2 header are unauthenticated, so the header is compared against the
# config and never trusted in its place (see src/config.rs).
#
# For each stage that has volumes, the module installs:
#
#   * a service that runs before anything is unlocked, with the three binaries
#     the daemon shells out to on its PATH;
#   * a drop-in on the systemd-cryptsetup@.service template, which is what
#     starts that service and what orders it first;
#   * a config listing only the volumes that stage unlocks, so each stage's
#     daemon serves exactly the volumes whose PCR state it is in a position to
#     capture.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.tpm2-autoenroll;

  volumesFor = stage: lib.filterAttrs (_: v: v.stage == stage) cfg.volumes;
  initrdVolumes = volumesFor "initrd";
  systemVolumes = volumesFor "system";
  inInitrd = initrdVolumes != { };
  inSystem = systemVolumes != { };

  configPath = "/etc/tpm2-autoenroll/config.json";

  # snake_case on the wire, camelCase in Nix.
  configFile =
    volumes:
    pkgs.writeText "tpm2-autoenroll.json" (
      builtins.toJSON {
        volumes = lib.mapAttrs (_: v: {
          inherit (v) device pcrs;
          tpm2_device = v.tpm2Device;
          pcr_bank = v.pcrBank;
        }) volumes;
      }
    );

  # /run survives switch-root, and the sockets the daemon binds live there. It
  # unlinks them when it is asked to stop, so being stopped at switch-root is
  # what keeps a dead socket out of stage 2's key-discovery path. Only
  # meaningful in the initrd; the system-stage copy omits both lines.
  teardown = [
    "initrd-switch-root.target"
    "shutdown.target"
  ];

  serviceUnit = initrd: systemdPackage: {
    description = "TPM2 auto-enrollment key agent";

    # Nothing here may acquire the ordinary boot dependencies: this has to be
    # listening before the volumes it serves are unlocked, which in the initrd
    # is long before sysinit.target.
    unitConfig.DefaultDependencies = "no";

    before = [
      "cryptsetup-pre.target"
      "cryptsetup.target"
    ]
    ++ lib.optionals initrd teardown;
    conflicts = lib.optionals initrd teardown;

    # The daemon shells out to systemd-ask-password, systemd-cryptenroll and
    # cryptsetup, and which systemd those come from differs by stage -- the
    # initrd's is boot.initrd.systemd.package. Stage 1 units get no default PATH
    # at all, so naming them is required there rather than merely tidy. The
    # package deliberately carries no PATH of its own so that this decision
    # belongs to the one place that knows the stage.
    path = [
      systemdPackage
      cfg.cryptsetupPackage
    ];

    serviceConfig = {
      # Type=notify is load-bearing rather than decorative. Under Type=exec
      # systemd would call the service started as soon as the binary was
      # executed, which is before it has read its config or bound anything, so
      # the After= in the drop-in below would order the unlock against nothing
      # useful. The daemon notifies once every socket is listening.
      Type = "notify";
      NotifyAccess = "main";
      ExecStart = "${lib.getExe cfg.package} --config=${configPath}";
    };
  };

  # Applies to every systemd-cryptsetup@<volume>.service the generator produces.
  # Wants= rather than Requires= so a daemon that fails to start costs the
  # feature and not the boot: After= is satisfied by a failed start as well as a
  # successful one, and the volume then unlocks exactly as it would with us
  # uninstalled.
  cryptsetupDropin = {
    overrideStrategy = "asDropin";
    text = ''
      [Unit]
      Wants=tpm2-autoenrolld.service
      After=tpm2-autoenrolld.service
    '';
  };

  volumeType = lib.types.submodule {
    options = {
      device = lib.mkOption {
        type = lib.types.strMatching "/.+";
        example = "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000";
        description = ''
          The backing block device: what holds the LUKS2 header, not the
          `/dev/mapper` node.
        '';
      };

      tpm2Device = lib.mkOption {
        type = lib.types.either (lib.types.enum [ "auto" ]) (lib.types.strMatching "/.+");
        default = "auto";
        description = ''
          `--tpm2-device=` for enrollment, and the device the daemon reads PCRs
          and lockout state from. "auto" means `/dev/tpmrm0`.
        '';
      };

      pcrs = lib.mkOption {
        type = lib.types.listOf (lib.types.ints.between 0 23);
        example = [
          0
          1
          7
        ];
        description = ''
          The PCR selection to enroll against. The daemon refuses to touch a
          volume whose header names a different selection.
        '';
      };

      pcrBank = lib.mkOption {
        type = lib.types.enum [
          "sha1"
          "sha256"
          "sha384"
          "sha512"
        ];
        default = "sha256";
        description = ''
          The PCR bank to enroll against. A header naming a different bank is
          refused, as with {option}`pcrs`.
        '';
      };

      stage = lib.mkOption {
        type = lib.types.enum [
          "initrd"
          "system"
        ];
        default = "initrd";
        description = ''
          Which stage this volume is unlocked in. The daemon has to run in that
          stage, because the PCR values read when it is consulted are the ones
          that will be present the next time the volume is unlocked at that same
          point in boot.
        '';
      };
    };
  };
in
{
  options.services.tpm2-autoenroll = {
    enable = lib.mkEnableOption "re-binding TPM2-enrolled LUKS2 volumes at the point of unlock";

    package = lib.mkOption {
      type = lib.types.package;
      description = "The tpm2-autoenrolld package to run.";
    };

    cryptsetupPackage = lib.mkOption {
      type = lib.types.package;
      default = pkgs.cryptsetup;
      defaultText = lib.literalExpression "pkgs.cryptsetup";
      description = ''
        Supplies the `cryptsetup` the daemon validates passphrases with. Kept
        separate from {option}`package` so it can be pinned to whatever built
        the headers being opened.
      '';
    };

    volumes = lib.mkOption {
      type = lib.types.attrsOf volumeType;
      default = { };
      example = lib.literalExpression ''
        {
          root = {
            device = "/dev/disk/by-uuid/...";
            pcrs = [ 0 1 7 ];
          };
          backup = {
            device = "/dev/disk/by-uuid/...";
            pcrs = [ 7 ];
            stage = "system";
          };
        }
      '';
      description = ''
        The volumes the daemon may act on, keyed by volume (mapper) name. The
        name has to match the crypttab entry: it is what the daemon's socket
        is named after and what systemd-cryptsetup identifies itself with.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.volumes != { };
        message = ''
          services.tpm2-autoenroll is enabled with no volumes, so nothing is
          installed anywhere. List them in services.tpm2-autoenroll.volumes.
        '';
      }
      {
        assertion = !inInitrd || config.boot.initrd.systemd.enable;
        message = ''
          services.tpm2-autoenroll has initrd volumes, which requires
          boot.initrd.systemd.enable. The whole mechanism is
          systemd-cryptsetup's key-discovery path; the scripted initrd does not
          have one.
        '';
      }
      {
        assertion = !inInitrd || config.boot.initrd.systemd.tpm2.enable;
        message = ''
          services.tpm2-autoenroll has initrd volumes, which requires
          boot.initrd.systemd.tpm2.enable so that /dev/tpmrm0 exists by the time
          systemd-cryptsetup runs. Without it there is no TPM2 unlock to fall
          back from and nothing to re-enroll.
        '';
      }
    ]
    ++ lib.mapAttrsToList (name: v: {
      assertion = v.pcrs != [ ];
      message = ''
        services.tpm2-autoenroll.volumes.${name}.pcrs is empty. A policy over no
        PCRs unseals unconditionally.
      '';
    }) cfg.volumes
    ++ lib.concatLists (
      lib.mapAttrsToList (
        name: _:
        let
          luks = config.boot.initrd.luks.devices.${name} or null;
        in
        [
          {
            assertion = luks != null;
            message = ''
              services.tpm2-autoenroll.volumes.${name} is an initrd volume, but
              there is no boot.initrd.luks.devices.${name}. The attribute name is
              the volume (mapper) name and has to match.
            '';
          }
          {
            assertion = luks == null || luks.keyFile == null;
            message = ''
              services.tpm2-autoenroll.volumes.${name} cannot be managed while
              boot.initrd.luks.devices.${name}.keyFile is set: with a key file,
              systemd-cryptsetup never searches for a discovered key, so it
              never contacts the daemon.
            '';
          }
          {
            assertion = luks == null || lib.any (lib.hasPrefix "tpm2-device=") luks.crypttabExtraOpts;
            message = ''
              services.tpm2-autoenroll.volumes.${name} is not TPM2-bound:
              boot.initrd.luks.devices.${name}.crypttabExtraOpts has no
              tpm2-device= entry, so there is no TPM2 unlock to fall back from.
            '';
          }
        ]
      ) initrdVolumes
    );

    boot.initrd.systemd = lib.mkIf inInitrd (
      let
        systemdPackage = config.boot.initrd.systemd.package;
      in
      {
        contents.${configPath}.source = configFile initrdVolumes;

        # One binary at a time rather than whole packages: the initrd builder
        # copies the closure of each path it is given, so naming the three
        # executables brings their shared libraries along without the rest of
        # systemd or cryptsetup. This is also why the daemon is unwrapped -- a
        # PATH wrapper would put both packages back in its own closure.
        storePaths = [
          cfg.package
          "${systemdPackage}/bin/systemd-ask-password"
          "${systemdPackage}/bin/systemd-cryptenroll"
          "${cfg.cryptsetupPackage}/bin/cryptsetup"
        ];

        services.tpm2-autoenrolld = serviceUnit true systemdPackage;
        units."systemd-cryptsetup@.service" = cryptsetupDropin;
      }
    );

    environment.etc = lib.mkIf inSystem {
      ${lib.removePrefix "/etc/" configPath}.source = configFile systemVolumes;
    };

    systemd.services.tpm2-autoenrolld = lib.mkIf inSystem (serviceUnit false config.systemd.package);

    systemd.units = lib.mkIf inSystem { "systemd-cryptsetup@.service" = cryptsetupDropin; };
  };
}
