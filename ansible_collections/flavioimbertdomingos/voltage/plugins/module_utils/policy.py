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

Beyond the basics, the parser reads three things the policy carries that most
monitoring ignores:

* **Key number tables** (`<keyNumberConfig><keyNumberTable name=.. currentNumber=..>`):
  the key-rotation mechanism. Rotation is an increment of `currentNumber`; old
  ciphertext still decrypts because the key number is recoverable. Seen in the
  public demo policy OpenText serves at voltage-pp-0000.dataprotection.voltage.com.
* **The appliance version** (`<server name="SecureDataAppliance" version="7.x"/>`),
  which makes support-lifecycle tracking free.
* **Enough about each format to estimate its domain size**, when the policy says
  (alphabet / length / preserved characters). NIST SP 800-38G Rev. 1 makes a minimum
  domain of 10^6 a *requirement* for FF1; a small-domain format is a cryptographic
  weakness the appliance will happily encrypt with.

This file is intentionally dependency-free (stdlib only) so the Ansible
collection's module_utils can carry an identical copy.
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field

_URL_RE = re.compile(r"https?://[^\s\"'<>]+")

#: NIST SP 800-38G Rev. 1 (2nd public draft, Feb 2025): the minimum domain size for FF1
#: and FF3-1 is one million, promoted from a recommendation to a requirement.
MIN_FPE_DOMAIN = 1_000_000

# Named alphabets a policy may reference instead of spelling the characters out.
_ALPHABETS = {
    "digits": 10,
    "numeric": 10,
    "digit": 10,
    "0-9": 10,
    "alpha": 52,
    "letters": 52,
    "alphabetic": 52,
    "a-za-z": 52,
    "upper": 26,
    "uppercase": 26,
    "a-z": 26,
    "lower": 26,
    "lowercase": 26,
    "alphanumeric": 62,
    "alnum": 62,
    "0-9a-za-z": 62,
    "upperalphanumeric": 36,
    "uppercasealphanumeric": 36,
    "0-9a-z": 36,
    "hex": 16,
    "hexadecimal": 16,
    "0-9a-f": 16,
    "ascii": 95,
    "printable": 95,
    "us7ascii": 95,
    "us7ascii-printable": 95,
    "unicode": 0,  # unbounded; treat as unknown
}


@dataclass
class KeyTable:
    """One `<keyNumberTable>`: a named list of key versions and the pointer to the current one."""

    name: str
    current_number: int | None = None
    keys: list[dict] = field(default_factory=list)  # {"number": int, "algorithm": str, "key_size": int|None}

    @property
    def current(self) -> dict | None:
        for k in self.keys:
            if k.get("number") == self.current_number:
                return k
        return None

    def to_dict(self) -> dict:
        return {"name": self.name, "current_number": self.current_number, "keys": list(self.keys)}


@dataclass
class PolicyInfo:
    version: str = ""
    district: str = ""
    policy_id: str = ""
    server_version: str = ""  # <server name="SecureDataAppliance" version="7.1.1.100286"/>
    formats: list[dict] = field(default_factory=list)  # {"name":..., "kind": "fpe"|"tokenization"|..., ...attrs}
    auth_methods: list[str] = field(default_factory=list)
    key_servers: list[str] = field(default_factory=list)
    key_tables: list[KeyTable] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    sha256: str = ""
    raw_attributes: dict = field(default_factory=dict)

    @property
    def format_names(self) -> list[str]:
        return [f["name"] for f in self.formats]

    @property
    def config_fingerprint(self) -> str:
        """sha256 of the *configuration* the policy expresses -- formats (with attributes), auth
        methods, key tables, server version -- and not of the bytes. Two appliances in the same
        district legitimately differ in hostnames and key-server URLs; they must not differ in
        this. Used for fleet agreement (R4)."""
        import json

        canon = {
            "version": self.version,
            "server_version": self.server_version,
            "formats": sorted((dict(sorted(f.items())) for f in self.formats), key=lambda f: f["name"]),
            "auth_methods": sorted(self.auth_methods),
            "key_tables": sorted((k.to_dict() for k in self.key_tables), key=lambda k: k["name"]),
        }
        return hashlib.sha256(json.dumps(canon, sort_keys=True, default=str).encode()).hexdigest()

    @property
    def efpe_formats(self) -> list[str]:
        return [f["name"] for f in self.formats if is_efpe(f)]

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "district": self.district,
            "policy_id": self.policy_id,
            "server_version": self.server_version,
            "config_fingerprint": self.config_fingerprint,
            "formats": self.formats,
            "auth_methods": self.auth_methods,
            "key_servers": self.key_servers,
            "key_tables": [k.to_dict() for k in self.key_tables],
            "efpe_formats": self.efpe_formats,
            "format_domain_sizes": {
                f["name"]: format_domain_size(f) for f in self.formats if format_domain_size(f) is not None
            },
            "urls": self.urls,
            "sha256": self.sha256,
        }


def _local(tag: str) -> str:
    """Strip an XML namespace: '{ns}Format' -> 'Format'."""
    return tag.rsplit("}", 1)[-1]


def _int(value: str | None) -> int | None:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None


def _attr(d: dict, *names: str) -> str | None:
    """Case-insensitive attribute lookup: first of `names` present in `d`."""
    low = {k.lower(): v for k, v in d.items()}
    for n in names:
        if n.lower() in low:
            return low[n.lower()]
    return None


# --------------------------------------------------------------------------- format analysis
def is_efpe(fmt: dict) -> bool:
    """Embedded FPE: the ciphertext carries a key identifier, so the same plaintext encrypts
    differently across key epochs (and equality joins on the column break). Vertica exposes
    it as a distinct format family; the policy attribute names are not public, so this looks
    for any of the obvious spellings."""
    for k, v in fmt.items():
        kl, vl = k.lower(), str(v).lower()
        if kl == "name":
            continue
        if "efpe" in vl or "embedded" in vl:
            return True
        if kl in ("efpe", "embeddedkey", "embedded_key", "embedkeynumber", "keyrotation") and vl in (
            "true",
            "1",
            "yes",
        ):
            return True
    return False


def alphabet_size(fmt: dict) -> int | None:
    """How many distinct characters each encrypted position can take, if the policy says."""
    n = _int(_attr(fmt, "alphabetSize", "radix", "charsetSize", "characterSetSize"))
    if n:
        return n
    alpha = _attr(fmt, "alphabet", "charset", "characterSet", "characters")
    if alpha is None:
        return None
    key = alpha.strip().lower()
    if key in _ALPHABETS:
        return _ALPHABETS[key] or None
    # an explicit list of characters, possibly with ranges like 0-9A-Z
    if re.fullmatch(r"(?:.-.|.)+", alpha) and "-" in alpha and len(alpha) <= 12:
        total = 0
        i = 0
        while i < len(alpha):
            if i + 2 < len(alpha) and alpha[i + 1] == "-":
                total += ord(alpha[i + 2]) - ord(alpha[i]) + 1
                i += 3
            else:
                total += 1
                i += 1
        return total or None
    return len(set(alpha)) or None


def encrypted_length(fmt: dict) -> int | None:
    """Positions that actually get encrypted: length minus preserved leading/trailing chars."""
    length = _int(_attr(fmt, "length", "minLength", "min_length", "digits", "size"))
    if length is None:
        return None
    max_len = _int(_attr(fmt, "maxLength", "max_length"))
    if max_len is not None and max_len < length:
        length = max_len
    lead = _int(_attr(fmt, "preserveLeading", "preserve_leading", "keepLeading", "leading", "prefix")) or 0
    trail = _int(_attr(fmt, "preserveTrailing", "preserve_trailing", "keepTrailing", "trailing", "suffix")) or 0
    return max(0, length - lead - trail)


def format_domain_size(fmt: dict) -> int | None:
    """radix ** encrypted_length, or None when the policy does not say enough.

    FPE only — tokenization and hash formats are not permutations on a domain. Uses the
    *minimum* length when a range is given, because the smallest domain is the weakest.
    """
    kind = str(fmt.get("kind", "")).lower()
    if kind and kind != "fpe":
        return None
    radix = alphabet_size(fmt)
    n = encrypted_length(fmt)
    if radix is None or n is None:
        return None
    if n == 0:
        return 1
    try:
        return radix**n
    except OverflowError:
        return None


# --------------------------------------------------------------------------- parse
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
                    # a format may describe itself in child elements rather than attributes
                    for sub in child:
                        stag = _local(sub.tag)
                        if stag.lower() != "name" and stag not in entry:
                            entry[stag] = (sub.text or "").strip() or sub.attrib.get("value", "")
                    info.formats.append(entry)
        # <AuthMethods><AuthMethod name="SharedSecret"/> or <authMethod>LDAP</authMethod>
        if "auth" in ptag and ptag.endswith("s"):
            for child in parent:
                name = child.attrib.get("name") or child.attrib.get("type") or (child.text or "").strip()
                if name and name not in info.auth_methods:
                    info.auth_methods.append(name)
        # <keyNumberTable name="PCI" currentNumber="4"><keyNumber number="1" algorithm="FPE" keySize="256"/>
        if ptag == "keynumbertable":
            table = KeyTable(
                name=_attr(parent.attrib, "name") or "default",
                current_number=_int(_attr(parent.attrib, "currentNumber", "current", "active")),
            )
            for child in parent:
                if _local(child.tag).lower() != "keynumber":
                    continue
                table.keys.append(
                    {
                        "number": _int(_attr(child.attrib, "number", "id", "keyNumber")),
                        "algorithm": _attr(child.attrib, "algorithm", "alg", "type") or "",
                        "key_size": _int(_attr(child.attrib, "keySize", "key_size", "bits", "size")),
                    }
                )
            if table.current_number is None and table.keys:
                table.current_number = max((k["number"] or 0) for k in table.keys)
            info.key_tables.append(table)
        # <server name="SecureDataAppliance" version="7.1.1.100286"/>
        if ptag == "server" and not info.server_version:
            info.server_version = _attr(parent.attrib, "version") or (parent.text or "").strip()

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
