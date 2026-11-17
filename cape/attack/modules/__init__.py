"""Attack modules for CAPE.

The basic modules perform bounded, non-destructive checks against local/private
lab targets. Legacy CMS, API and Network workflows remain available separately.
"""
from cape.attack.modules.basic import (
    AuthModule,
    DirectoryEnumerationModule,
    HTTPHeadersModule,
    SMBModule,
    SQLiModule,
    XSSModule,
)
from cape.attack.modules.api import APIModule
from cape.attack.modules.smb import CMSModule, NetworkModule

AVAILABLE_MODULES = {
    "SQLiModule": SQLiModule,
    "XSSModule": XSSModule,
    "SMBModule": SMBModule,
    "AuthModule": AuthModule,
    "DirectoryEnumerationModule": DirectoryEnumerationModule,
    "HTTPHeadersModule": HTTPHeadersModule,
    "CMSModule": CMSModule,
    "NetworkModule": NetworkModule,
    "APIModule": APIModule,
}

__all__ = list(AVAILABLE_MODULES.keys()) + ["AVAILABLE_MODULES"]
