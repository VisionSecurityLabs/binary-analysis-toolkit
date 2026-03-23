"""PE manifest extraction — assembly identity, execution level, compatibility."""

import xml.etree.ElementTree as ET

import pefile

from binanalysis.output import heading, info, detail, warn


_NS = {
    "asm1": "urn:schemas-microsoft-com:asm.v1",
    "asm3": "urn:schemas-microsoft-com:asm.v3",
    "compat": "urn:schemas-microsoft-com:compatibility.v1",
}

_SUPPORTED_OS = {
    "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}": "Windows 10 / 11",
    "{1f676c76-80e1-4239-95bb-83d0f6d0da78}": "Windows 7",
    "{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}": "Windows Vista",
    "{35138b9a-5d96-4fbd-8e2d-a2440225f93a}": "Windows 8.1",
    "{e2011457-1546-43c5-a5fe-008deee3d3f0}": "Windows 8",
}


def extract_manifest(pe: pefile.PE, data: bytes) -> dict:
    """Extract and parse the RT_MANIFEST resource from a PE binary."""
    heading("PE MANIFEST")

    result = {}

    manifest_xml = _get_manifest_xml(pe)
    if not manifest_xml:
        info("No manifest found")
        return result

    result["raw"] = manifest_xml

    try:
        root = ET.fromstring(manifest_xml)
    except ET.ParseError:
        info("Manifest found but could not be parsed as XML")
        return result

    # Assembly identity
    identity = root.find("asm1:assemblyIdentity", _NS)
    if identity is not None:
        result["name"] = identity.get("name", "")
        result["version"] = identity.get("version", "")
        result["processor_architecture"] = identity.get("processorArchitecture", "")
        result["type"] = identity.get("type", "")
        if result["name"]:
            detail("Assembly Name", result["name"])
        if result["version"]:
            detail("Version", result["version"])

    # Description
    desc = root.find("asm1:description", _NS)
    if desc is not None and desc.text:
        result["description"] = desc.text.strip()
        detail("Description", result["description"])

    # Requested execution level
    exec_level = root.find(
        ".//asm3:requestedExecutionLevel", _NS
    )
    if exec_level is not None:
        level = exec_level.get("level", "")
        ui_access = exec_level.get("uiAccess", "false")
        result["execution_level"] = level
        result["ui_access"] = ui_access
        detail("Execution Level", level)
        if level == "requireAdministrator":
            warn("Requests administrator privileges")
        elif level == "highestAvailable":
            warn("Requests highest available privileges")

    # Supported OS compatibility
    compat_app = root.find(".//compat:application", _NS)
    if compat_app is not None:
        supported = []
        for os_elem in compat_app.findall("compat:supportedOS", _NS):
            os_id = os_elem.get("Id", "")
            os_name = _SUPPORTED_OS.get(os_id, os_id)
            supported.append(os_name)
        if supported:
            result["supported_os"] = supported
            detail("Supported OS", ", ".join(supported))

    # DPI awareness
    dpi = root.find(".//{http://schemas.microsoft.com/SMI/2005/WindowsSettings}dpiAware")
    if dpi is not None and dpi.text:
        result["dpi_aware"] = dpi.text.strip()

    if not result:
        info("Manifest present but contains no notable fields")

    return result


def _get_manifest_xml(pe: pefile.PE) -> str | None:
    """Extract the RT_MANIFEST resource string from the PE."""
    RT_MANIFEST = 24

    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None

    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id != RT_MANIFEST:
            continue
        for dir_entry in entry.directory.entries:
            for res in dir_entry.directory.entries:
                offset = res.data.struct.OffsetToData
                size = res.data.struct.Size
                try:
                    raw = pe.get_data(offset, size)
                    return raw.decode("utf-8", errors="replace").strip()
                except Exception:
                    return None
    return None
