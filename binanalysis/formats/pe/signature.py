"""Authenticode signature extraction — signer, issuer, validity from PE certificate table."""

import struct
import hashlib
import datetime

import pefile

from binanalysis.output import heading, info, detail, warn


def analyze_signature(pe: pefile.PE, data: bytes) -> dict:
    """Parse the PE certificate table and extract Authenticode signer info."""
    heading("DIGITAL SIGNATURE (AUTHENTICODE)")

    result = {}

    # Check for certificate table in data directory
    cert_entry = pe.OPTIONAL_HEADER.DATA_DIRECTORY[
        pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]
    ]

    if cert_entry.VirtualAddress == 0 or cert_entry.Size == 0:
        result["signed"] = False
        info("No digital signature found (unsigned binary)")
        return result

    result["signed"] = True
    result["cert_table_offset"] = hex(cert_entry.VirtualAddress)
    result["cert_table_size"] = cert_entry.Size
    info("Digital signature present")
    detail("Certificate Offset", hex(cert_entry.VirtualAddress))
    detail("Certificate Size", f"{cert_entry.Size} bytes")

    # Extract the raw certificate data
    offset = cert_entry.VirtualAddress
    size = cert_entry.Size

    if offset + size > len(data):
        warn("Certificate table extends beyond file — possibly truncated")
        return result

    cert_data = data[offset:offset + size]

    # Parse WIN_CERTIFICATE structure
    # DWORD dwLength, WORD wRevision, WORD wCertificateType, BYTE bCertificate[]
    if len(cert_data) < 8:
        return result

    dw_length, w_revision, w_cert_type = struct.unpack_from("<IHH", cert_data, 0)
    result["cert_revision"] = hex(w_revision)
    result["cert_type"] = {
        0x0001: "X.509",
        0x0002: "PKCS#7 SignedData",
    }.get(w_cert_type, f"Unknown ({hex(w_cert_type)})")
    detail("Certificate Type", result["cert_type"])

    # The actual PKCS#7 blob starts at offset 8
    pkcs7_data = cert_data[8:dw_length]
    if not pkcs7_data:
        return result

    # Extract signer info by parsing DER-encoded X.509 fields from the PKCS#7 blob
    signer_info = _extract_signer_fields(pkcs7_data)
    result.update(signer_info)

    if signer_info.get("signer"):
        detail("Signer", signer_info["signer"])
    if signer_info.get("issuer"):
        detail("Issuer", signer_info["issuer"])
    if signer_info.get("serial_hex"):
        detail("Serial", signer_info["serial_hex"])
    if signer_info.get("thumbprint"):
        detail("Thumbprint (SHA-1)", signer_info["thumbprint"])

    return result


def _extract_signer_fields(pkcs7_data: bytes) -> dict:
    """Best-effort extraction of signer CN and issuer from DER-encoded PKCS#7.

    This is a lightweight parser that doesn't require pyOpenSSL/cryptography.
    It searches for common OID patterns in the DER data to find CN fields.
    """
    result = {}

    # Compute thumbprint of the raw certificate data
    result["thumbprint"] = hashlib.sha1(pkcs7_data).hexdigest()

    # OID for commonName: 2.5.4.3 → 55 04 03
    cn_oid = b"\x55\x04\x03"
    # OID for organizationName: 2.5.4.10 → 55 04 0a
    org_oid = b"\x55\x04\x0a"

    cns = _find_oid_values(pkcs7_data, cn_oid)
    orgs = _find_oid_values(pkcs7_data, org_oid)

    # In PKCS#7, CA names (DigiCert, Sectigo, etc.) repeat many times.
    # The actual signer CN typically appears only once or few times.
    # Find the CN that is NOT a well-known CA.
    ca_keywords = {"digicert", "sectigo", "comodo", "verisign", "globalsign",
                   "entrust", "godaddy", "symantec", "thawte", "geotrust",
                   "timestamp", "root", "intermediate"}

    signer_cn = None
    issuer_cn = None
    for cn in cns:
        if any(kw in cn.lower() for kw in ca_keywords):
            if issuer_cn is None:
                issuer_cn = cn
        else:
            if signer_cn is None:
                signer_cn = cn

    if signer_cn:
        result["signer"] = signer_cn
    elif cns:
        result["signer"] = cns[0]

    if issuer_cn:
        result["issuer"] = issuer_cn
    elif len(cns) >= 2:
        result["issuer"] = cns[0]

    # Find the non-CA organization
    for org in orgs:
        if not any(kw in org.lower() for kw in ca_keywords):
            result["signer_organization"] = org
            break

    return result


def _find_oid_values(data: bytes, oid: bytes) -> list[str]:
    """Find all string values following an OID in DER-encoded data."""
    values = []
    search_from = 0

    while True:
        idx = data.find(oid, search_from)
        if idx == -1:
            break

        # After the OID, there's a string type tag and length
        pos = idx + len(oid)
        if pos + 2 >= len(data):
            break

        tag = data[pos]
        length = data[pos + 1]

        # Common string types: UTF8String(0x0c), PrintableString(0x13), IA5String(0x16), BMPString(0x1e)
        if tag in (0x0c, 0x13, 0x16):
            if pos + 2 + length <= len(data):
                val = data[pos + 2:pos + 2 + length].decode("utf-8", errors="replace")
                if val and len(val) > 1:
                    values.append(val)
        elif tag == 0x1e:  # BMPString (UTF-16BE)
            if pos + 2 + length <= len(data):
                val = data[pos + 2:pos + 2 + length].decode("utf-16-be", errors="replace")
                if val and len(val) > 1:
                    values.append(val)

        search_from = idx + 1

    return values
