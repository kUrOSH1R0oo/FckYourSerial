"""
fckyourserial — ASP.NET ViewState RCE payload generator.

A cross-platform, Python-only replacement for ysoserial's TypeConfuseDelegate
ViewState gadget, including modern SP800-108 key derivation (ASP.NET 4.5+).
"""

__version__ = "1.0.0"
__author__  = "kur0sh1ro"

from .gadgets import generate_viewstate
from .crypto import encrypt_and_sign, sp800_108_derivekey

__all__ = [
    "generate_viewstate",
    "encrypt_and_sign",
    "sp800_108_derivekey",
    "__version__",
]
