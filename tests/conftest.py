"""Load protocol/client without importing the HA-dependent package __init__."""
import sys, types, pathlib

PKG = pathlib.Path(__file__).parent.parent / "custom_components" / "germguardian"
pkg = types.ModuleType("germguardian")
pkg.__path__ = [str(PKG)]
sys.modules.setdefault("germguardian", pkg)
