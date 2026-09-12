# The NixOS module -- DESIGN.md section 7.
#
# Its whole job is to put three things in the right place for each stage a
# managed volume is unlocked in:
#
#   * a .socket listening on /run/cryptsetup-keys.d/<volume>.key, which is the
#     key-discovery path systemd-cryptsetup consults on every iteration of its
#     unlock loop (2.3);
#   * the .service it activates;
#   * the config file that tells the daemon which volumes it may act on and what
#     backing device sits behind each (7.1).
#
# The daemon is stage-agnostic (9.1) -- it takes its volumes from that file and
# its sockets from LISTEN_FDS, and nothing in it knows whether it is in the
# initrd. So this module is not namespaced under boot.initrd either; each volume
# says which stage it is unlocked in and the same pair of units is emitted into
# the matching place.
{
  config,
  lib,
  pkgs,
  utils,
  ...
}:

let
  cfg = config.services.tpm2-autoenroll;

  volumesForStage = stage: lib.filterAttrs (_: v: v.stage == stage) cfg.volumes;

  initrdVolumes = volumesForStage "initrd";
  systemVolumes = volumesForStage "system";

  # A per-volume override falls back to the global. null rather than a value is
  # what makes "unset" distinguishable from "set to the same thing the global
  # happens to be", so a later change to the global still reaches the volume.
  orGlobal = global: v: if v == null then global else v;

  pcrsOf = v: orGlobal cfg.tpm2Pcrs v.tpm2Pcrs;

  # Values arrive at the daemon already resolved: the module merges its globals
  # here so exactly one component knows what a default is, and config.rs stays a
  # flat read (7.1).
  configFile =
    volumes:
    pkgs.writeText "tpm2-autoenroll.json" (
      builtins.toJSON {
        volumes = builtins.mapAttrs (_: v: {
          inherit (v) device;
          tpm2Device = orGlobal cfg.tpm2Device v.tpm2Device;
          tpm2Pcrs = pcrsOf v;
          enrollIfAbsent = orGlobal cfg.enrollIfAbsent v.enrollIfAbsent;
        }) volumes;
      }
    );

  configPath = "/etc/tpm2-autoenroll/config.json";

  socketPath = volume: "/run/cryptsetup-keys.d/${volume}.key";

  cryptsetupUnit = volume: "systemd-cryptsetup@${utils.escapeSystemdPath volume}.service";

  # /run survives switch-root, and stopping the socket unit is what unlinks the
  # socket file. Without this the initrd would leave a dead socket sitting
  # exactly where stage 2's systemd-cryptsetup looks for a discovered key, and a
  # system-stage unlock would connect to nobody. Only meaningful in the initrd,
  # so the system-stage copy of each unit omits it (3.1).
  teardown = [
    "initrd-switch-root.target"
    "shutdown.target"
  ];

  socketUnit = initrd: volumes: {
    description = "TPM2 auto-enrollment key socket";

    # Nothing here may acquire the ordinary boot dependencies: this has to be
    # listening before the volumes it serves are unlocked, which in the initrd
    # is long before sysinit.target.
    unitConfig.DefaultDependencies = "no";

    # Two anchors, deliberately. cryptsetup-pre.target is the documented one
    # (3.1), but it carries RefuseManualStart=yes and is only pulled in by the
    # cryptsetup generator, so ordering against it is inert if it never starts.
    # The per-instance Wants/Before is what actually guarantees we are listening,
    # and it names exactly the units that would otherwise find no socket. This
    # is the shape nixpkgs' own clevis unit uses (luksroot.nix).
    before = [
      "cryptsetup-pre.target"
    ]
    ++ map cryptsetupUnit (lib.attrNames volumes)
    ++ lib.optionals initrd teardown;
    wantedBy = map cryptsetupUnit (lib.attrNames volumes);
    conflicts = lib.optionals initrd teardown;

    socketConfig = {
      ListenStream = map socketPath (lib.attrNames volumes);
      Accept = "no";
      SocketMode = "0600";
      # systemd.socket(5): the parent directories of a ListenStream= path are
      # created automatically, and this is the mode they get. That covers
      # /run/cryptsetup-keys.d without a tmpfiles.d entry whose ordering in the
      # initrd we would otherwise have to prove is early enough.
      DirectoryMode = "0700";
    };
  };

  # Socket-activated, so it is never wantedBy anything: the first connection
  # from systemd-cryptsetup starts it, and on a boot where every volume unlocks
  # from its header token it is never started at all (2.4).
  serviceUnit = initrd: systemdPackage: {
    description = "TPM2 auto-enrollment daemon";
    unitConfig.DefaultDependencies = "no";
    before = lib.optionals initrd teardown;
    conflicts = lib.optionals initrd teardown;

    # The daemon shells out to systemd-ask-password, systemd-cryptenroll and
    # cryptsetup (section 9), and which systemd those come from differs by
    # stage -- the initrd's is boot.initrd.systemd.package. Stage 1 units get
    # no default PATH at all, so naming them is required there rather than
    # merely tidy. The package deliberately carries no PATH of its own so that
    # this decision belongs to the one place that knows the stage.
    path = [
      systemdPackage
      cfg.cryptsetupPackage
    ];

    serviceConfig = {
      Type = "exec";
      ExecStart = "${lib.getExe cfg.package} --config=${configPath}";
    };
  };

  volumeType = lib.types.submodule {
    options = {
      device = lib.mkOption {
        type = lib.types.str;
        example = "/dev/disk/by-uuid/00000000-0000-0000-0000-000000000000";
        description = ''
          The backing block device -- what holds the LUKS2 header, not the
          `/dev/mapper` node. The daemon validates the passphrase against it
          and hands it to `systemd-cryptenroll`, so a volume without one
          cannot be managed.
        '';
      };

      stage = lib.mkOption {
        type = lib.types.enum [
          "initrd"
          "system"
        ];
        default = "initrd";
        description = ''
          Which stage this volume is unlocked in. The units are emitted into
          that stage, because the design's invariant is to enroll at the point
          of unlock: the PCR values read when the daemon is consulted are the
          ones that will be present the next time this volume is unlocked at
          that same point in boot.
        '';
      };

      tpm2Device = lib.mkOption {
        type = lib.types.nullOr lib.types.str;
        default = null;
        description = "Overrides {option}`services.tpm2-autoenroll.tpm2Device` for this volume.";
      };

      tpm2Pcrs = lib.mkOption {
        type = lib.types.nullOr (lib.types.listOf (lib.types.ints.between 0 23));
        default = null;
        description = ''
          Overrides {option}`services.tpm2-autoenroll.tpm2Pcrs` for this volume.

          Only consulted under {option}`enrollIfAbsent`. Repairing a drifted
          binding reproduces the selection and bank of the token it replaces,
          because narrowing or widening an existing binding is a policy change
          and not one to make silently on a fallback path (4.2).
        '';
      };

      enrollIfAbsent = lib.mkOption {
        type = lib.types.nullOr lib.types.bool;
        default = null;
        description = "Overrides {option}`services.tpm2-autoenroll.enrollIfAbsent` for this volume.";
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
        Supplies the `cryptsetup` the daemon validates passphrases with (3.3).
        Kept separate from {option}`package` so it can be pinned to whatever
        built the headers being opened.
      '';
    };

    tpm2Device = lib.mkOption {
      type = lib.types.str;
      default = "auto";
      description = ''
        Default `--tpm2-device=` for enrollment, and the device the daemon reads
        PCRs and lockout state from. "auto" means `/dev/tpmrm0`.
      '';
    };

    tpm2Pcrs = lib.mkOption {
      type = lib.types.listOf (lib.types.ints.between 0 23);
      default = [ 7 ];
      description = ''
        Default PCR selection for volumes enrolled from scratch under
        {option}`enrollIfAbsent`. A repair reproduces the selection it replaces
        instead (4.2).
      '';
    };

    enrollIfAbsent = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Whether a volume carrying no `systemd-tpm2` token may be enrolled from
        scratch. Off by default, so the daemon only repairs bindings that
        already existed and drifted, and a volume that was never meant to be
        TPM2-bound is left alone.
      '';
    };

    volumes = lib.mkOption {
      type = lib.types.attrsOf volumeType;
      default = { };
      example = lib.literalExpression ''
        {
          root.device = "/dev/disk/by-uuid/...";
          backup = {
            device = "/dev/disk/by-uuid/...";
            stage = "system";
          };
        }
      '';
      description = ''
        The volumes the daemon may act on, keyed by **volume (mapper) name**.

        That name must match the crypttab entry, because it is what appears both
        in the socket path the daemon listens on and in the abstract bindname
        systemd-cryptsetup connects from -- the two halves of how one daemon
        serves many volumes.
      '';
    };
  };

  config = lib.mkIf (cfg.enable && cfg.volumes != { }) {
    assertions = [
      {
        assertion = initrdVolumes == { } || config.boot.initrd.systemd.enable;
        message = ''
          services.tpm2-autoenroll: ${lib.concatStringsSep ", " (lib.attrNames initrdVolumes)} are unlocked in the initrd, which requires boot.initrd.systemd.enable.
          The whole mechanism is systemd-cryptsetup's key-discovery path; the
          scripted initrd does not have one.
        '';
      }
      {
        assertion = initrdVolumes == { } || config.boot.initrd.systemd.tpm2.enable;
        message = ''
          services.tpm2-autoenroll: ${lib.concatStringsSep ", " (lib.attrNames initrdVolumes)} are unlocked in the initrd, which requires boot.initrd.systemd.tpm2.enable
          so that /dev/tpmrm0 exists by the time systemd-cryptsetup runs. Without
          it there is no TPM2 unlock to fall back from and nothing to re-enroll.
        '';
      }
    ]
    ++ lib.mapAttrsToList (volume: _: {
      assertion = config.boot.initrd.luks.devices ? ${volume};
      message = ''
        services.tpm2-autoenroll.volumes.${volume} has stage = "initrd" but there
        is no boot.initrd.luks.devices.${volume}. The attribute name is the
        volume (mapper) name and has to match the crypttab entry, which is what
        the socket path and the bindname are both built from.
      '';
    }) initrdVolumes
    ++ lib.mapAttrsToList (volume: _: {
      assertion =
        !(config.boot.initrd.luks.devices ? ${volume})
        || config.boot.initrd.luks.devices.${volume}.keyFile == null;
      message = ''
        services.tpm2-autoenroll.volumes.${volume} cannot be managed while
        boot.initrd.luks.devices.${volume}.keyFile is set.

        A key file in crypttab's third field makes systemd-cryptsetup take the
        key-file branch unconditionally (cryptsetup.c:2044) and leaves
        try_discover_key false, so the LUKS2 header token is never consulted and
        this daemon is never contacted. The volume would prompt for a passphrase
        on every boot -- see DESIGN.md section 2.2.
      '';
    }) initrdVolumes;

    # 9.1's footgun. PCRs 11 and up keep being extended by userspace after the
    # point a system-stage volume is unlocked, so such a volume would seal
    # against a state that has already moved on and fall back on every boot.
    # That follows from the PCR choice rather than from this tool, but the tool
    # makes it easy to arrive at by accident, which is what earns a warning.
    warnings =
      let
        volatile = v: lib.filter (p: p >= 11) (pcrsOf v);
      in
      lib.mapAttrsToList (
        volume: v:
        "services.tpm2-autoenroll.volumes.${volume} has stage = \"system\" and binds to"
        + " PCR ${lib.concatMapStringsSep ", " toString (volatile v)}, which userspace keeps"
        + " extending after that volume is unlocked. Enrolling against it would seal to a"
        + " state that never recurs at unlock time, so the volume would fall back to a"
        + " passphrase on every boot."
      ) (lib.filterAttrs (_: v: v.stage == "system" && volatile v != [ ]) cfg.volumes);

    boot.initrd.systemd = lib.mkIf (initrdVolumes != { }) (
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

        sockets.tpm2-autoenrolld = socketUnit true initrdVolumes;
        services.tpm2-autoenrolld = serviceUnit true systemdPackage;
      }
    );

    environment.etc.${lib.removePrefix "/etc/" configPath} = lib.mkIf (systemVolumes != { }) {
      source = configFile systemVolumes;
    };

    systemd.sockets.tpm2-autoenrolld = lib.mkIf (systemVolumes != { }) (socketUnit false systemVolumes);

    systemd.services.tpm2-autoenrolld = lib.mkIf (systemVolumes != { }) (
      serviceUnit false config.systemd.package
    );
  };
}
