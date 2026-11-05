# Third-party references and notices

The source manifests in `references/` record upstream URLs, commit IDs, and
SHA-256 digests used during development. The referenced C sources are not needed
at runtime and are not bundled with this project. The pinned upstream URLs
provide the original source files and their license notices.

## lldpd

LLDP/CDP protocol handling was researched using lldpd. The CDP checksum in
`cdp.py` follows `src/daemon/frame.c`, including Cisco's odd-byte behavior.
`cdp-sources.json` and `lldpd-source.json` identify the exact upstream versions.
The LLDP and CDP reference files carry Copyright (c) 2008 Vincent Bernat;
the checksum reference carries the following notice:

```text
Copyright (c) 2009 Vincent Bernat <bernat@luffy.cx>

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

```

## Linux USB and Realtek references

`references/sources.json` identifies the Linux sources used to verify USB ABI,
register definitions, and controller revision interpretation:

- `drivers/net/usb/r8152.c`: GPL-2.0-only; Copyright (c) 2014 Realtek Semiconductor Corp.
- `include/linux/usb/r8152.h`: GPL-2.0-only; Copyright (c) 2020 Realtek Semiconductor Corp.
- `include/uapi/linux/usbdevice_fs.h`: GPL-2.0+ WITH Linux-syscall-note; Copyright (C) 2000 Thomas Sailer.

The ABI check compiles against the installed system headers. These references
are not linked or compiled into the Python application. Their licenses and
copyright notices remain applicable to the upstream files.

## Project licensing

No blanket license has been selected for this project's original code. Public
repository visibility alone does not grant an open-source license. Third-party
notices above remain applicable independently of a future project license.
