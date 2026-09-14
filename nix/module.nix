# The NixOS module.
#
# There is very little for it to do, which is the point. The daemon finds its
# volumes in /etc/crypttab at runtime, so this module never enumerates them; it
# only has to put the daemon in the right place in the boot, for each stage the
# user says their volumes are unlocked in:
#
#   * a service that runs before anything is unlocked, with the three binaries
#     the daemon shells out to on its PATH;
#   * a drop-in on the systemd-cryptsetup@.service template, which is what
#     starts that service and what orders it first;
#   * the ignore list, if the user has opted any volume out.
#
# The drop-in is where the socket-per-volume problem goes away. A .socket unit
# has to name its ListenStream= paths at build time, which would mean this
# module re-deriving the volume list -- possible for boot.initrd.luks.devices,
# not possible for a hand-written stage-2 crypttab. Since the template drop-in
# applies to every instance without naming any of them, the daemon can bind its
# own sockets from whatever it finds in the crypttab, and the two halves stay
# out of each other's way.
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.tpm2-autoenroll;

  inInitrd = lib.elem "initrd" cfg.stages;
  inSystem = lib.elem "systemd" cfg.stages;

  ignorePath = "/etc/tpm2-autoenroll/ignore";
  ignoreFile = pkgs.writeText "tpm2-autoenroll-ignore" (
    lib.concatMapStrings (entry: entry + "\n") cfg.ignore
  );
  haveIgnore = cfg.ignore != [ ];

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
      # executed, which is before it has read the crypttab or bound anything, so
      # the After= in the drop-in below would order the unlock against nothing
      # useful. The daemon notifies once every socket is listening.
      Type = "notify";
      NotifyAccess = "main";
      ExecStart = lib.getExe cfg.package;
    };
  };

  # Applies to every systemd-cryptsetup@<volume>.service the generator produces,
  # without this module having to know what any of them are called. Wants=
  # rather than Requires= so a daemon that fails to start costs the feature and
  # not the boot: After= is satisfied by a failed start as well as a successful
  # one, and the volume then unlocks exactly as it would with us uninstalled.
  cryptsetupDropin = {
    overrideStrategy = "asDropin";
    text = ''
      [Unit]
      Wants=tpm2-autoenrolld.service
      After=tpm2-autoenrolld.service
    '';
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
      type = lib.types.listOf (
        lib.types.enum [
          "initrd"
          "systemd"
        ]
      );
      default = [ "initrd" ];
      example = [
        "systemd"
        "initrd"
      ];
      description = ''
        Which boot stages to run the daemon in: `initrd` for volumes unlocked
        by the systemd initrd, `systemd` for those unlocked by the booted
        system. In each one it manages the TPM2-bound volumes of that stage's
        own `/etc/crypttab`, so listing a stage with no such volumes is
        harmless.

        This is per stage rather than per volume because the design's invariant
        is to enroll at the point of unlock: the PCR values read when the
        daemon is consulted are the ones that will be present the next time
        that volume is unlocked at that same point in boot.
      '';
    };

    ignore = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      example = [ "swap" ];
      description = ''
        Volumes that must never be re-enrolled, and never prompt. An entry
        matches either the volume (mapper) name or the backing device, and
        device specs are resolved the way crypttab resolves them, so
        `UUID=...` means here what it means there.

        Everything else that is TPM2-bound in the crypttab is managed; there is
        no list to add a volume to.
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.stages != [ ];
        message = ''
          services.tpm2-autoenroll is enabled with no stages, so nothing is
          installed anywhere. Set services.tpm2-autoenroll.stages to the stages
          your TPM2-bound volumes are unlocked in.
        '';
      }
      {
        assertion = !inInitrd || config.boot.initrd.systemd.enable;
        message = ''
          services.tpm2-autoenroll has "initrd" in its stages, which requires
          boot.initrd.systemd.enable. The whole mechanism is
          systemd-cryptsetup's key-discovery path; the scripted initrd does not
          have one.
        '';
      }
      {
        assertion = !inInitrd || config.boot.initrd.systemd.tpm2.enable;
        message = ''
          services.tpm2-autoenroll has "initrd" in its stages, which requires
          boot.initrd.systemd.tpm2.enable so that /dev/tpmrm0 exists by the time
          systemd-cryptsetup runs. Without it there is no TPM2 unlock to fall
          back from and nothing to re-enroll.
        '';
      }
    ];

    boot.initrd.systemd = lib.mkIf inInitrd (
      let
        systemdPackage = config.boot.initrd.systemd.package;
      in
      {
        contents = lib.mkIf haveIgnore { ${ignorePath}.source = ignoreFile; };

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

    environment.etc = lib.mkIf (inSystem && haveIgnore) {
      ${lib.removePrefix "/etc/" ignorePath}.source = ignoreFile;
    };

    systemd.services.tpm2-autoenrolld = lib.mkIf inSystem (serviceUnit false config.systemd.package);

    systemd.units = lib.mkIf inSystem { "systemd-cryptsetup@.service" = cryptsetupDropin; };
  };
}
