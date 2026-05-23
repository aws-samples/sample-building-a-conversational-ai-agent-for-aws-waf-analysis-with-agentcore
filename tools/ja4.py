# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0
"""JA4 fingerprint analysis tool — structural interpretation without external database."""

from strands import tool


# JA4 first character: protocol
_PROTO = {"t": "TCP/TLS", "q": "QUIC", "d": "DTLS"}
# JA4 third character: SNI
_SNI = {"d": "domain SNI present", "i": "IP-based (no SNI)"}


@tool
def lookup_ja4(fingerprints: str) -> str:
    """Analyze JA4 TLS fingerprints by decoding their structural components.

    JA4 fingerprints are self-describing: the first 10 characters encode protocol,
    TLS version, SNI presence, cipher count, and extension count. This tool decodes
    that structure to help identify client type (browser vs automation).

    Note: This tool does NOT identify specific applications. For application-level
    identification, cross-reference with User-Agent and behavioral patterns from
    analyze_ip or detect_bypass.

    Args:
        fingerprints: Comma-separated JA4 fingerprint strings to analyze.
            Example: "t13d1516h2_8daaf6152771_02713d6af862"

    Returns:
        Structural analysis of each fingerprint.
    """
    fps = [fp.strip() for fp in fingerprints.split(",") if fp.strip()]
    if not fps:
        return "No fingerprints provided."

    lines = ["## JA4 Fingerprint Analysis", ""]
    for fp in fps[:25]:
        lines.append(f"**{fp}**")
        parts = fp.split("_")
        if len(parts) != 3 or len(parts[0]) < 10:
            lines.append("  (invalid format)")
            lines.append("")
            continue

        prefix = parts[0]
        # Decode prefix: [proto][version][sni][cipher_count][ext_count][alpn]
        proto = _PROTO.get(prefix[0], f"unknown({prefix[0]})")
        version = prefix[1:3]  # TLS version: 13=1.3, 12=1.2, etc.
        sni = _SNI.get(prefix[3], f"unknown({prefix[3]})")
        cipher_count = prefix[4:6]
        ext_count = prefix[6:8]
        alpn = prefix[8:10]

        tls_ver = {"13": "TLS 1.3", "12": "TLS 1.2", "11": "TLS 1.1", "10": "TLS 1.0"}.get(version, f"TLS ?({version})")

        try:
            cipher_n = int(cipher_count)
            ext_n = int(ext_count)
        except ValueError:
            cipher_n = 0
            ext_n = 0

        lines.append(f"  Protocol: {proto}")
        lines.append(f"  TLS Version: {tls_ver}")
        lines.append(f"  SNI: {sni}")
        lines.append(f"  Cipher suites: {cipher_n} offered")
        lines.append(f"  Extensions: {ext_n}")
        lines.append(f"  ALPN: {'h2' if alpn == 'h2' else 'http/1.1' if alpn == 'h1' else alpn}")
        lines.append(f"  Hash segments: {parts[1]}_{parts[2]}")

        # Heuristic signals
        signals = []
        if version == "13" and cipher_n >= 12 and ext_n >= 15:
            signals.append("modern browser profile (TLS 1.3 + many ciphers/extensions)")
        elif version == "12" and cipher_n < 8:
            signals.append("minimal TLS stack — likely automation tool or library")
        if alpn == "h2":
            signals.append("HTTP/2 capable")
        if prefix[3] == "i":
            signals.append("no SNI — unusual for browsers, common in scripts")

        if signals:
            lines.append(f"  Signals: {'; '.join(signals)}")
        lines.append("")

    lines.append("---")
    lines.append("Note: JA4 fingerprints alone cannot definitively identify applications.")
    lines.append("Cross-reference with: User-Agent, request frequency, URI patterns.")
    lines.append("Same JA4 across multiple IPs = same TLS library (possible botnet).")
    lines.append("Multiple UAs but single JA4 = UA spoofing (same client rotating UAs).")
    return "\n".join(lines)
