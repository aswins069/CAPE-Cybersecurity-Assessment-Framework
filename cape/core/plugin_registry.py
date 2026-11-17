"""Plugin registry for scan engine plugins."""
from __future__ import annotations

from typing import Optional, Type


class PluginRegistry:
    """Registry mapping plugin names to plugin classes.

    Plugins self-register by calling register().
    """

    def __init__(self) -> None:
        """Initialize empty registry."""
        self._registry: dict[str, Type] = {}

    def register(self, name: str, plugin_class: Type) -> None:
        """Register a plugin class by name."""
        self._registry[name] = plugin_class

    def get(self, name: str) -> Optional[Type]:
        """Get plugin class by name, or None if not found."""
        return self._registry.get(name)

    def all_names(self) -> list[str]:
        """Return list of all registered plugin names."""
        return list(self._registry.keys())

    def all_plugins(self) -> dict[str, Type]:
        """Return full registry dict."""
        return dict(self._registry)


_registry = PluginRegistry()


def get_registry() -> PluginRegistry:
    """Get the global plugin registry."""
    return _registry


def register_plugin(name: str, plugin_class: Type) -> None:
    """Register a plugin in the global registry."""
    _registry.register(name, plugin_class)
