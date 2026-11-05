# Android Termux LLDP CLI

**Find out where that Ethernet wall socket goes—using your Android phone.**

Whether you work in IT or run a home lab, tracing a wall socket to its switch port can save time when troubleshooting or documenting cabling. Android Termux LLDP CLI turns a compatible Android phone and supported Realtek RTL8153 USB Ethernet adapter into a simple switch-port discovery tool.

Connect the adapter to the wall socket, open Termux, and run `lldp`. When the connected switch advertises LLDP, the tool can show its name, port description or ID, and management address. It also reports observed tagged VLANs and the untagged VLAN when advertised. **No root or switch login is required.**

For basic switch-port identification, this may save you from reaching for a dedicated network tester. It does not replace cable certification, wire-map testing, or other physical cable diagnostics.

```sh
lldp
```

The command listens for 10 seconds and reports LLDP discovery, observed tagged VLANs, and an advertised untagged VLAN when available. It also listens for CDP. USB setup, permission prompts, and recovery add time to the receive window.

Example output uses fictional values:

```text
Ethernet:      1000 Mbps, full duplex (before scan)
Switch:        example-switch
Port:          Ethernet 1/1/24
Switch IP:     192.0.2.10
Untagged VLAN: Unknown
Tagged VLANs:  100 (observed)
```

## Requirements

- Standard Termux on little-endian ARM64 Android, using `/data/data/com.termux/files/`.
- The Termux:API Android app **and** the `termux-api` command-line package.
- Python 3 and Git for installation. No additional Python packages are required.
- Realtek adapter VID `0BDA`, PID `8153`, exposing the expected CDC-ECM configuration 2, control interface 0, data interface 1, and bulk-IN endpoint `0x81`.
- Ethernet traffic and a switch advertising LLDP or CDP for discovery.

Real LLDP and tagged VLAN reception have been verified on one unrooted Android/Termux setup with an RTL8153C adapter. Other adapters and phones are not verified. CDP decoding has automated coverage; live CDP reception has not yet been confirmed.

Capture temporarily takes control of the adapter and switches USB configuration. Android Ethernet connectivity is interrupted during the scan. The tester attempts to restore the original configuration afterward; unplug and reconnect if Ethernet does not recover. The working capture path does not load firmware, write Realtek registers, or transmit network probes.

## Install

Install [Termux](https://github.com/termux/termux-app#installation) and [Termux:API](https://github.com/termux/termux-api#installation) from matching sources, for example both from F-Droid. Installing the command-line package does not install the Android add-on app.

In Termux:

```sh
pkg update && pkg install -y python termux-api git
```

Clone and install the command:

```sh
(
  set -eu
  if test -e "$HOME/android-termux-lldp-cli" || test -L "$HOME/android-termux-lldp-cli"; then
    printf '%s\n' 'Project directory already exists; use the update instructions.'
    exit 1
  fi
  if test -e "$PREFIX/bin/lldp" || test -L "$PREFIX/bin/lldp"; then
    printf '%s\n' 'An lldp command already exists; inspect it before replacing it.'
    exit 1
  fi
  git clone https://github.com/shine104/android-termux-lldp-cli.git "$HOME/android-termux-lldp-cli"
  chmod 700 "$HOME/android-termux-lldp-cli/"*.sh
  cat > "$PREFIX/bin/lldp" <<'LAUNCHER'
#!/data/data/com.termux/files/usr/bin/sh
exec /data/data/com.termux/files/usr/bin/python "$HOME/android-termux-lldp-cli/ecm_capture.py" --execute "$@"
LAUNCHER
  chmod 700 "$PREFIX/bin/lldp"
  lldp --help
)
```

Until the repository becomes public, cloning requires GitHub authentication with an account that has access. Existing private-repository users can run `gh auth login` and `gh auth setup-git` after installing `gh`. Public cloning requires no GitHub account.

Keep the project in Termux home, not shared Android storage: USB callbacks need executable permissions. Connect the adapter and cable, run `lldp`, and accept the Android USB permission prompt.

## Results

| Field | Meaning |
| --- | --- |
| Ethernet | Negotiated 10/100/1000 Mbps link speed and duplex, read before the scan changes USB mode. `Link down` means the link was down at that time; `Unknown` means no usable reading. This is not a throughput test. |
| Switch / Port | Advertised switch name and port description, with port ID as fallback. A CDP-only result is labeled CDP. |
| Switch IP | Advertised switch management address; omitted when absent. This is not the phone's Ethernet IP. |
| Untagged VLAN | LLDP PVID or a matching CDP native-VLAN advertisement. `Unknown` means no usable value was received. Conflicting advertisements are reported explicitly. |
| Tagged VLANs | VLAN IDs observed in received frames, not a complete list of VLANs allowed on the port. `None observed` does not prove there are no tagged VLANs. |

Untagged frames contain no VLAN number. The tool cannot infer that number from IP addresses. Priority-only VID 0 tags are not VLAN membership. Missing or expired advertisements are not presented as current discovery. A 10-second scan may miss periodic advertisements; retry if needed.

Phone Ethernet IP/subnet, gateway, DNS, DHCP testing, and an Android APK are not implemented. Voice VLAN policies, when advertised, are available in verbose diagnostics.

Speed reporting uses read-only PHY requests on the verified RTL8153C revision while USB configuration 1 is active. If the adapter is already in configuration 2, the revision is unverified, or a read fails, discovery continues with speed shown as `Unknown`. The reading is a snapshot before capture; the link may renegotiate during USB setup or recovery. Detailed reasons and the reading timestamp are available with `--verbose`.

## Diagnostics and troubleshooting

```sh
lldp --verbose
```

Logs are saved under `~/android-termux-lldp-cli/logs/` and ignored by Git. They contain LLDP frames and network identifiers such as switch names, ports, and management addresses. Review or redact a log before sharing it. Unrelated traffic contributes tag metadata and counters only; its payloads are not saved.

| Problem | Action |
| --- | --- |
| USB permission denied | Accept the Android USB prompt; reconnect and retry if needed. |
| Interface busy | Close other USB apps, reconnect the adapter, and retry. |
| No discovery result | Check the cable and switch advertisements; retry to allow for periodic packets. |
| Untagged VLAN unknown | The switch must supply an applicable advertisement; no value is invented. |
| Ethernet fails after capture | Unplug/reconnect and inspect recovery errors with `--verbose`. |
| `termux-usb` missing or unresponsive | Check both Termux:API installations and matching app sources. |

To select among multiple connected USB devices, run `termux-usb -l`, then use `lldp --device /dev/bus/usb/BBB/DDD` with the current adapter path. Paths change after reconnection.

Read-only compatibility inspection:

```sh
python "$HOME/android-termux-lldp-cli/ecm_capture.py"
```

Additional read-only USB and controller diagnostics:

```sh
python "$HOME/android-termux-lldp-cli/diagnostic.py"
```

## Update

The repository starts with a single `Initial release` commit. If your installation
uses the earlier development history, clone the repository again into a new
directory instead of merging unrelated histories. Preserve any local changes
and private logs separately, then place the fresh clone at
`~/android-termux-lldp-cli` so the existing `lldp` launcher can find it.

Stop any capture, then update without overwriting divergent local history:

```sh
git -C "$HOME/android-termux-lldp-cli" pull --ff-only
```

## Development and transfer archives

Offline tests use synthetic packets and mock USB devices:

```sh
cd "$HOME/android-termux-lldp-cli"
python -m unittest discover -s tests -q
```

Some tests print simulated permission errors; the final `OK` indicates success. Tests do not establish compatibility with another phone. To check the ARM64 USB ABI against installed system headers, install `clang` and run:

```sh
clang -fsyntax-only tests/check_usb_abi.c
```

Create an archive of committed files only. Ignored logs, local credentials, caches, and uncommitted changes are not included:

```sh
git -C "$HOME/android-termux-lldp-cli" archive \
  --format=tar.gz --prefix=android-termux-lldp-cli/ \
  --output="$HOME/android-termux-lldp-cli-transfer.tar.gz" HEAD
```

## References and licensing

Pinned source URLs and hashes are listed in [references](references/README.md). See [third-party notices](THIRD_PARTY_NOTICES.md) for the upstream references and checksum attribution.

A project-wide license for the original code has not yet been selected. Repository visibility does not change third-party notices or grant an open-source license by itself.
