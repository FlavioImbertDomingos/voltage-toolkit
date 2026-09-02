"""Parse a Voltage SecureData `clientPolicy.xml`.

(Identical to exporter/voltage_exporter/policy.py -- keep the two in sync; the exporter tests cover it.)

Every SecureData client (Simple API, Web Services, the Vertica/Hadoop integrations)
starts by downloading `https://voltage-pp-0000.<domain>/policy/clientPolicy.xml`.
That file is the one public, unauthenticated, documented touch-point of a
SecureData deployment: it lists the formats the district offers, the key server
addresses and the authentication methods. If it is unreachable, *nothing* can
tokenize.

OpenText does not publish the XML schema, and it varies by release. So this parser
is deliberately forgiving: it walks the whole tree and collects anything that
looks like a format, an auth method or a URL, and exposes the raw attributes too.
Override the element names via `xpaths` in config if your policy differs.

This file is intentionally dependency-free (stdlib only) so the Ansible
collection's module_utils can carry an identical copy.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")


@dataclass
class PolicyInfo:
    version: str = ""
    district: str = ""
    policy_id: str = ""
    formats: list[dict] = field(default_factory=list)  # {"name":..., "kind": "fpe"|"tokenization"|..., ...attrs}
    auth_methods: list[str] = field(default_factory=list)
    key_servers: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sha256: str = ""
    raw_attributes: dict = field(default_factory=dict)

    @property
    def format_names(self) -> list[str]:
        return [f["name"] for f in self.formats]

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "district": self.district,
            "policy_id": self.policy_id,
            "formats": self.formats,
            "auth_methods": self.auth_methods,
            "key_servers": self.key_servers,
            "urls": self.urls,
            "sha256": self.sha256,
        }


def _local(tag: str) -> str:
    """Strip an XML namespace: '{ns}Format' -> 'Format'."""
    return tag.rsplit("}", 1)[-1]


def parse_policy(xml_text: str | bytes) -> PolicyInfo:
    data = xml_text.encode() if isinstance(xml_text, str) else xml_text
    root = ET.fromstring(data)
    info = PolicyInfo(sha256=hashlib.sha256(data).hexdigest())

    ra = {k.lower(): v for k, v in root.attrib.items()}
    info.raw_attributes = dict(root.attrib)
    info.version = ra.get("version", "") or ra.get("policyversion", "")
    info.district = ra.get("district", "") or ra.get("districtname", "")
    info.policy_id = ra.get("policyid", "") or ra.get("id", "")

    seen_formats: set[str] = set()
    for parent in root.iter():
        ptag = _local(parent.tag).lower()
        # <FormatMappings><Format name="CC" .../></FormatMappings>, <TokenizationFormats><Format .../>
        if "format" in ptag and ptag.endswith("s"):
            kind = "tokenization" if "token" in ptag else "fpe" if ("fpe" in ptag or "mapping" in ptag) else ptag
            for child in parent:
                name = child.attrib.get("name") or child.attrib.get("Name") or (child.text or "").strip()
                if name and name not in seen_formats:
                    seen_formats.add(name)
                    entry = {"name": name, "kind": kind}
                    entry.update({k: v for k, v in child.attrib.items() if k.lower() != "name"})
                    info.formats.append(entry)
        # <AuthMethods><AuthMethod name="SharedSecret"/> or <authMethod>LDAP</authMethod>
        if "auth" in ptag and ptag.endswith("s"):
            for child in parent:
                name = child.attrib.get("name") or child.attrib.get("type") or (child.text or "").strip()
                if name and name not in info.auth_methods:
                    info.auth_methods.append(name)

    # district may live on a child element rather than the root
    if not info.district:
        for el in root.iter():
            if _local(el.tag).lower() in ("district", "districtname"):
                info.district = (el.attrib.get("name") or el.text or "").strip()
                if info.district:
                    break

    # every URL anywhere; key servers are the ones that look like key/vibe endpoints
    text_blob = data.decode(errors="replace")
    for url in dict.fromkeys(_URL_RE.findall(text_blob)):
        info.urls.append(url)
        low = url.lower()
        if "key" in low or "vibe" in low or "ks-" in low:
            info.key_servers.append(url)
    for el in root.iter():
        if "keyserver" in _local(el.tag).lower():
            url = el.attrib.get("url") or el.attrib.get("href") or (el.text or "").strip()
            if url and url not in info.key_servers:
                info.key_servers.append(url)
    return info
