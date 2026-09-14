# tpm2-autoenroll

tpm2-autoenroll is a service for automatically re-enrolling new PCR states using systemd-cryptsetup.

## Usage

On boot, systemd will attempt to decrypt your TPM2 backed devices.

If it fails, it will fall through to attempting to discover keys. It will discover tpm2-autoenroll.
tpm2-autoenroll will prompt you for a password, and verify it against the device.
tpm2-autoenroll with then prompt you for a re-enrollment decision. There are three options:
1. Yes - enroll this PCR state for this device
2. Always - enroll this PCR state for this device, and remember this decision for futures devices with identical PCR state
3. No - do not enroll this PCR state for any device

Regardless of your choice, your password will be passed back to systemd to unlock the disk.
Boot continues as normal.

## Packaging

Build the binary, and run it as a systemd unit.
The unit should:

1. Set `DefaultDependencies=no`
2. Run before and conflict with `initrd-switch-root` and `shutdown` targets.
3. Run before `cryptsetup-pre.target` 
4. Run before and be wanted by `systemd-cryptsetup@$VOLUME.service` for each volume.

`systemd-cryptenroll` and `systemd-ask-password` must be in `$PATH`.

TODO: write a dracut module, maybe.

## Configuration

Most users should not require any configuration.
On start, tpm2-autoenroll will find disks configured to unlock with tpm in `/etc/crypttab`.
The TPM device will be detected from `/etc/crypttab`.
The PCRs will be detected from the `systemd-tpm2` token data.

If you want to ignore a device and never be prompted for re-enrollment, put the device name (matching crypttab) in `/etc/tmp2-autoenroll/ignore`, one per line.

### NixOS

A nixos module and flake is present. Configuration example is present below.

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
    "swap" = {
      device = "/dev/disk/by-uuid/abc";
      crypttabExtraOpts = [
        "tpm2-device=auto"
        "tpm2-measure-pcr=yes"
      ];
    };
  };
  services.tpm2-autoenroll {
    enable = true;
    stages = [ "systemd" "initrd" ];
    ignore = [ "/dev/disk/by-uuid/abc" ];
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

## Notes

Don't trust any documentation outside of README.md, it's all LLM generated and therefore mostly terrible.
