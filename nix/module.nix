# The NixOS module.
#
# Each volume is listed explicitly, under the stage that unlocks it, with the
# PCR selection it is to be enrolled against. That list is the daemon's only
# source of policy: the same fields in the LUKS2 header are unauthenticated, so
# the header is compared against the config and never trusted in its place (see
# src/config.rs).
#
# A stage's `volumes` attrset is the daemon's JSON config verbatim: the options
# are named after the wire keys, and the volume submodule is freeform, so a key
# this module has never heard of still reaches the daemon. The daemon rejects a
# volume carrying a key it does not know, so a typo costs that volume the
# feature at boot rather than failing the build.
#
# For each stage that has volumes, the module installs:
#
#   * a service that runs before anything is unlocked, with the three binaries
#     the daemon shells out to on its PATH;
#   * a drop-in on the systemd-cryptsetup@.service template, which is what
#     starts that service and what orders it first;
#   * that stage's config, so each stage's daemon serves exactly the volumes
#     whose PCR state it is in a position to capture.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.tpm2-autoenroll;

  format = pkgs.formats.json { };

  initrdVolumes = cfg.stages.initrd.volumes;
  systemVolumes = cfg.stages.system.volumes;
  inInitrd = initrdVolumes != { };
  inSystem = systemVolumes != { };

  configPath = "/etc/tpm2-autoenroll/config.json";

  # The daemon validates the generated file here, at build time, because the
  # volume submodule is freeform: a key it does not recognise gets this far
  # without Nix noticing, and at boot that costs the volume the feature while
  # saying so only in the journal. Skipped when the build machine cannot run the
  # binary, as on a cross build, which is then the one case where a config the
  # daemon would refuse still reaches a boot.
  checked =
    file:
    if pkgs.stdenv.buildPlatform.canExecute pkgs.stdenv.hostPlatform then
      pkgs.runCommand "tpm2-autoenroll.json" { } ''
        ${lib.getExe cfg.package} check-config --config=${file}
        cp ${file} $out
      ''
    else
      file;

  configFile = volumes: checked (format.generate "tpm2-autoenroll.json" { inherit volumes; });

  # The daemon refuses to hand a passphrase to a peer whose /proc/<pid>/exe is
  # not the systemd-cryptsetup it was built expecting (src/peer.rs). That path
  # is baked in at compile time because there is nothing trustworthy to read it
  # from at runtime, and its built-in default is the /usr/bin location a
  # conventional distribution uses, which no NixOS system has. So the package
  # is rebuilt per stage against the systemd that stage actually runs. Both
  # stages normally share one -- boot.initrd.systemd.package defaults to
  # config.systemd.package -- so this is usually a single extra build.
  packageFor =
    systemdPackage:
    cfg.package.overrideAttrs {
      TPM2_AUTOENROLL_SYSTEMD_CRYPTSETUP = "${systemdPackage}/bin/systemd-cryptsetup";
    };

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
      ExecStart = "${lib.getExe (packageFor systemdPackage)} --config=${configPath}";
      LimitCORE = "0";

      # Sandboxing that takes nothing the daemon uses. It needs block devices,
      # the TPM and its sockets in /run, so nothing here restricts devices or
      # /run: not PrivateDevices or DevicePolicy, and not ProtectClock either,
      # which implies a DeviceAllow= list and so closes off every other device.
      NoNewPrivileges = true;
      LockPersonality = true;
      SystemCallArchitectures = "native";
      RestrictRealtime = true;
      RestrictSUIDSGID = true;
      SystemCallFilter = "@system-service";
      MemoryDenyWriteExecute = "yes";
      UMask = "0077";
      # libcryptsetup can decrypt keyslots through AF_ALG and talks to udev and
      # device-mapper over netlink; everything else is AF_UNIX.
      RestrictAddressFamilies = [
        "AF_UNIX"
        "AF_ALG"
        "AF_NETLINK"
      ];
    }
    # Stage 2 only. No test boots the initrd, and these all rest on mount
    # namespacing there that nothing has exercised. PrivateTmp adds no mount
    # dependencies here: with DefaultDependencies=no it becomes "disconnected".
    // lib.optionalAttrs (!initrd) {
      ProtectHome = true;
      PrivateTmp = true;
      ProtectKernelModules = true;
      ProtectKernelLogs = true;
      ProtectHostname = true;
      RestrictNamespaces = true;
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
    # The config file's schema is the daemon's, not this module's. Declaring
    # the four keys it has today buys type checking and documentation; the
    # freeform type is what keeps a fifth from needing a module release.
    freeformType = format.type;

    options = {
      device = lib.mkOption {
        type = lib.types.strMatching "/.+";
        example = "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000";
        description = ''
          The backing block device: what holds the LUKS2 header, not the
          `/dev/mapper` node.
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

      tpm2_device = lib.mkOption {
        type = lib.types.either (lib.types.enum [ "auto" ]) (lib.types.strMatching "/.+");
        default = "auto";
        description = ''
          `--tpm2-device=` for enrollment, and the device the daemon reads PCRs
          and lockout state from. "auto" means `/dev/tpmrm0`.
        '';
      };

      pcr_bank = lib.mkOption {
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
    };
  };

  stageType = lib.types.submodule {
    options.volumes = lib.mkOption {
      type = lib.types.attrsOf volumeType;
      default = { };
      example = lib.literalExpression ''
        {
          root = {
            device = "/dev/disk/by-uuid/...";
            pcrs = [ 0 1 7 ];
          };
        }
      '';
      description = ''
        The volumes this stage's daemon may act on, keyed by volume (mapper)
        name. The name has to match the crypttab entry: it is what the daemon's
        socket is named after and what systemd-cryptsetup identifies itself
        with.

        This attrset is written to the daemon's config as its `volumes` object
        verbatim, so an attribute this module does not declare is passed
        through untouched -- and rejected by the daemon if it does not know it,
        which leaves that volume unlocking as if the tool were not installed.
      '';
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

    stages = lib.mkOption {
      default = { };
      example = lib.literalExpression ''
        {
          initrd.volumes.root = {
            device = "/dev/disk/by-uuid/...";
            pcrs = [ 0 1 7 ];
          };
          system.volumes.backup = {
            device = "/dev/disk/by-uuid/...";
            pcrs = [ 7 ];
          };
        }
      '';
      description = ''
        The volumes to manage, grouped by the stage that unlocks them. A
        volume's daemon has to run in that stage, because the PCR values read
        when it is consulted are the ones that will be present the next time
        the volume is unlocked at that same point in boot. Each stage gets its
        own service and its own config listing only its own volumes.
      '';
      type = lib.types.submodule {
        options = {
          initrd = lib.mkOption {
            type = stageType;
            default = { };
            description = "Volumes unlocked in the initrd.";
          };

          system = lib.mkOption {
            type = stageType;
            default = { };
            description = "Volumes unlocked after switch-root, in stage 2.";
          };
        };
      };
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = inInitrd || inSystem;
        message = ''
          services.tpm2-autoenroll is enabled with no volumes, so nothing is
          installed anywhere. List them in
          services.tpm2-autoenroll.stages.<initrd|system>.volumes.
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
    ++ lib.concatLists (
      lib.mapAttrsToList
        (
          stage: volumes:
          lib.mapAttrsToList (name: v: {
            assertion = v.pcrs != [ ];
            message = ''
              services.tpm2-autoenroll.stages.${stage}.volumes.${name}.pcrs is
              empty. A policy over no PCRs unseals unconditionally.
            '';
          }) volumes
        )
        {
          initrd = initrdVolumes;
          system = systemVolumes;
        }
    )
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
              services.tpm2-autoenroll.stages.initrd.volumes.${name} has no
              boot.initrd.luks.devices.${name}. The attribute name is the volume
              (mapper) name and has to match.
            '';
          }
          {
            assertion = luks == null || luks.keyFile == null;
            message = ''
              services.tpm2-autoenroll.stages.initrd.volumes.${name} cannot be
              managed while boot.initrd.luks.devices.${name}.keyFile is set:
              with a key file, systemd-cryptsetup never searches for a
              discovered key, so it never contacts the daemon.
            '';
          }
          {
            assertion = luks == null || lib.any (lib.hasPrefix "tpm2-device=") luks.crypttabExtraOpts;
            message = ''
              services.tpm2-autoenroll.stages.initrd.volumes.${name} is not
              TPM2-bound: boot.initrd.luks.devices.${name}.crypttabExtraOpts has
              no tpm2-device= entry, so there is no TPM2 unlock to fall back
              from.
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
          (packageFor systemdPackage)
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
