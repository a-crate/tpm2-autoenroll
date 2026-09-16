# tpm2-autoenroll

tpm2-autoenroll is a service for automatically re-enrolling new PCR states using systemd-cryptsetup.

## Usage

On boot, systemd will attempt to decrypt your TPM2 backed devices.

If it fails, it will fall through to attempting to discover keys. It will discover tpm2-autoenroll.
tpm2-autoenroll will prompt you for a password, and verify it against the device.
tpm2-autoenroll with then prompt you for a re-enrollment decision. There are three options:
1. Yes - enroll this PCR state for this device
2. Always - enroll this PCR state for this device, and remember this decision for future devices with identical PCR state this run
3. No - do not enroll this PCR state for any device this run

Regardless of your choice, your password will be passed back to systemd to unlock the disk.
Boot continues as normal.

## Packaging

Build the binary, and run it as a systemd unit.
The unit should:

1. Set `DefaultDependencies=no` and `Type=notify`
2. Run before and conflict with `initrd-switch-root` and `shutdown` targets.
3. Run before `cryptsetup-pre.target` 
4. Run before and be wanted by `systemd-cryptsetup@$VOLUME.service` for each volume. This can be done with a `system-cryptsetup@.service` drop in.

`cryptsetup`, `systemd-cryptenroll`, and `systemd-ask-password` must be in `$PATH`.

TODO: write a dracut module, maybe.

## Configuration

Describe the devices to be re-enrolled in `/etc/tpm2-autoenroll/config.json`.
Fields described below.

```json
{
  "volumes": { // (required) top-level key
    "<name>": { // device mapper name
      "device": "", // (required) backing device
      "tpm2_device": "", // (default: auto) tpm2 device,
      "pcrs": [ 0 ], // (required) PCRs, no PCRs may be >23,
      "pcr_bank": "", // (default: sha256) pcr bank,
    }
  }
}
```

You can check your current settings by running 
`DEV=/dev/sda1 sudo cryptsetup luksDump --dump-json-metadata $DEV | jq '.tokens | to_entries[] | select(.value.type=="systemd-tpm2")'`

### NixOS

A nixos module and flake is present.
Flake configuration looks something like this:

```nix
{
  description = "NixOS configuration";

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixpkgs-unstable";
    tpm2-autoenroll.url = "github:a-crate/tpm2-autoenroll";
  };

  outputs = inputs@{ nixpkgs, tpm2-autoenroll, ... }: {
    nixosConfigurations = {
      hostname = nixpkgs.lib.nixosSystem {
        system = "x86_64-linux";
        modules = [
          ./configuration.nix
          tpm2-autoenroll.nixosModules.default
        ];
      };
    };
  };
}
```

And actual usage looks something like this:

```nix
{
  boot.initrd.luks.devices = {
    "root" = {
      device = "/dev/disk/by-uuid/def";
      crypttabExtraOpts = [
        "tpm2-device=auto"
        "tpm2-measure-pcr=yes"
      ];
    };
  };
  environment.etc.crypttab = {
      mode = "0600";
      text = ''
        # <volume-name> <encrypted-device> [key-file] [options]
        swap /dev/disk/by-uuid/abc - tpm2-device=auto,tpm2-measure-pcr=yes
      '';
    };
  services.tpm2-autoenroll = {
    enable = true;
    initrd.volumes = {
      "root" = {
        device = "/dev/disk/by-uuid/def";
        pcrs = [ 0 1 7 ];
      };
    };
    system.volumes = {
      "swap" = {
        device = "/dev/disk/by-uuid/abc";
        pcrs = [ 0 1 7 ];
      };
    };
  };
}
```

### /etc/crypttab

You should configure systemd to unlock your devices using TPM2 as normal using `/etc/crypttab`.
You should _not_ set a keyfile option in `/etc/crypttab` - this will bypass the key discovery path and skip tpm2-autoenroll.

## Security Considerations

Usage of this module increases your susceptibility to evil maid attacks.

Accepting re-enrollment when you were not expecting a change in PCRs could leak your disk encryption keys to an attacker.
However, typing in your password at all when you were not expecting a change in PCRs could leak your keys to an attacker.

## AI Policy

The use of AI or LLMs to wholly or partially write the following things is forbidden:
* Direct communication with humans.
  This includes pull request titles, description, and comments.
* Documentation files in this repository. This includes markdown documentation, but does _not_ include code comments.
  Documentation intended to be read solely by AI (such as CLAUDE.md or AGENTS.md) may be AI authored.

All other usage of AI is welcome and permitted.
