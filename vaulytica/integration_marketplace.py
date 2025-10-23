"""
Integration Marketplace for Vaulytica.

Provides plugin system, community marketplace, and SDK for custom integrations.
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from uuid import uuid4
import importlib
import inspect

logger = logging.getLogger(__name__)


# ==================== Enums ====================

class PluginType(str, Enum):
    """Types of plugins."""
    DATA_SOURCE = "data_source"
    ALERT_DESTINATION = "alert_destination"
    ENRICHMENT = "enrichment"
    ANALYSIS = "analysis"
    AUTOMATION = "automation"
    VISUALIZATION = "visualization"
    EXPORT = "export"
    CUSTOM = "custom"


class PluginStatus(str, Enum):
    """Plugin status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    INSTALLING = "installing"
    UNINSTALLING = "uninstalling"


class MarketplaceCategory(str, Enum):
    """Marketplace categories."""
    THREAT_INTELLIGENCE = "threat_intelligence"
    SIEM_INTEGRATION = "siem_integration"
    TICKETING = "ticketing"
    CLOUD_SECURITY = "cloud_security"
    ENDPOINT_SECURITY = "endpoint_security"
    NETWORK_SECURITY = "network_security"
    COMPLIANCE = "compliance"
    AUTOMATION = "automation"
    ANALYTICS = "analytics"
    REPORTING = "reporting"


# ==================== Data Models ====================

@dataclass
class PluginMetadata:
    """Metadata for a plugin."""
    plugin_id: str
    name: str
    version: str
    description: str
    author: str
    plugin_type: PluginType
    category: MarketplaceCategory
    homepage: Optional[str] = None
    documentation_url: Optional[str] = None
    license: str = "MIT"
    tags: List[str] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    min_vaulytica_version: str = "0.32.0"
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class Plugin:
    """Represents a plugin."""
    metadata: PluginMetadata
    status: PluginStatus
    module: Optional[Any] = None
    config: Dict[str, Any] = field(default_factory=dict)
    installed_at: Optional[datetime] = None
    last_used: Optional[datetime] = None
    usage_count: int = 0
    error_message: Optional[str] = None


@dataclass
class MarketplaceListing:
    """Marketplace listing for a plugin."""
    listing_id: str
    plugin_metadata: PluginMetadata
    download_url: str
    install_count: int = 0
    rating: float = 0.0
    review_count: int = 0
    screenshots: List[str] = field(default_factory=list)
    verified: bool = False
    featured: bool = False
    published_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PluginHook:
    """Hook point for plugins."""
    hook_name: str
    description: str
    parameters: Dict[str, type]
    return_type: type
    callbacks: List[Callable] = field(default_factory=list)


# ==================== Plugin Base Class ====================

class BasePlugin:
    """Base class for all plugins."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the plugin."""
        self.config = config or {}
        self.logger = logging.getLogger(self.__class__.__name__)

    async def initialize(self) -> bool:
        """Initialize the plugin. Override in subclass."""
        return True

    async def execute(self, **kwargs) -> Any:
        """Execute the plugin. Override in subclass."""
        raise NotImplementedError("Plugin must implement execute method")

    async def cleanup(self) -> None:
        """Cleanup resources. Override in subclass."""
        pass

    def get_metadata(self) -> PluginMetadata:
        """Get plugin metadata. Override in subclass."""
        raise NotImplementedError("Plugin must implement get_metadata method")


# ==================== Integration Marketplace ====================

class IntegrationMarketplace:
    """
    Integration marketplace for plugins and custom integrations.

    Provides:
    - Plugin management
    - Community marketplace
    - SDK for custom integrations
    - Hook system for extensibility
    """

    def __init__(self):
        """Initialize the marketplace."""
        self.plugins: Dict[str, Plugin] = {}
        self.listings: Dict[str, MarketplaceListing] = {}
        self.hooks: Dict[str, PluginHook] = {}
        self._initialize_hooks()
        logger.info("Integration marketplace initialized")

    def _initialize_hooks(self):
        """Initialize plugin hooks."""
        # Data ingestion hook
        self.register_hook(
            "data_ingestion",
            "Called when new data is ingested",
            {"data": dict, "source": str},
            dict
        )

        # Alert processing hook
        self.register_hook(
            "alert_processing",
            "Called when an alert is processed",
            {"alert": dict},
            dict
        )

        # Enrichment hook
        self.register_hook(
            "enrichment",
            "Called to enrich data",
            {"data": dict, "context": dict},
            dict
        )

        # Analysis hook
        self.register_hook(
            "analysis",
            "Called to perform analysis",
            {"data": dict},
            dict
        )

        # Export hook
        self.register_hook(
            "export",
            "Called to export data",
            {"data": dict, "format": str},
            str
        )

    # ==================== Plugin Management ====================

    async def install_plugin(
        self,
        plugin_metadata: PluginMetadata,
        module_path: Optional[str] = None
    ) -> Plugin:
        """Install a plugin."""
        logger.info(f"Installing plugin: {plugin_metadata.name} v{plugin_metadata.version}")

        plugin = Plugin(
            metadata=plugin_metadata,
            status=PluginStatus.INSTALLING,
            installed_at=datetime.utcnow()
        )

        try:
            # Load plugin module if provided
            if module_path:
                module = importlib.import_module(module_path)
                plugin.module = module

            # Initialize plugin
            if plugin.module:
                plugin_class = self._find_plugin_class(plugin.module)
                if plugin_class:
                    instance = plugin_class(plugin.config)
                    await instance.initialize()

            plugin.status = PluginStatus.ACTIVE
            self.plugins[plugin_metadata.plugin_id] = plugin

            logger.info(f"Plugin installed successfully: {plugin_metadata.name}")
            return plugin

        except Exception as e:
            logger.error(f"Failed to install plugin: {e}")
            plugin.status = PluginStatus.ERROR
            plugin.error_message = str(e)
            raise

    def _find_plugin_class(self, module: Any) -> Optional[type]:
        """Find the plugin class in a module."""
        for name, obj in inspect.getmembers(module):
            if inspect.isclass(obj) and issubclass(obj, BasePlugin) and obj != BasePlugin:
                return obj
        return None

    async def uninstall_plugin(self, plugin_id: str) -> bool:
        """Uninstall a plugin."""
        plugin = self.plugins.get(plugin_id)
        if not plugin:
            logger.warning(f"Plugin not found: {plugin_id}")
            return False

        logger.info(f"Uninstalling plugin: {plugin.metadata.name}")

        try:
            plugin.status = PluginStatus.UNINSTALLING

            # Cleanup plugin
            if plugin.module:
                plugin_class = self._find_plugin_class(plugin.module)
                if plugin_class:
                    instance = plugin_class(plugin.config)
                    await instance.cleanup()

            # Remove from registry
            del self.plugins[plugin_id]

            logger.info(f"Plugin uninstalled: {plugin.metadata.name}")
            return True

        except Exception as e:
            logger.error(f"Failed to uninstall plugin: {e}")
            plugin.status = PluginStatus.ERROR
            plugin.error_message = str(e)
            return False

    def get_plugin(self, plugin_id: str) -> Optional[Plugin]:
        """Get a plugin by ID."""
        return self.plugins.get(plugin_id)

    def list_plugins(
        self,
        plugin_type: Optional[PluginType] = None,
        status: Optional[PluginStatus] = None
    ) -> List[Plugin]:
        """List installed plugins."""
        plugins = list(self.plugins.values())

        if plugin_type:
            plugins = [p for p in plugins if p.metadata.plugin_type == plugin_type]

        if status:
            plugins = [p for p in plugins if p.status == status]

        return plugins

    async def execute_plugin(self, plugin_id: str, **kwargs) -> Any:
        """Execute a plugin."""
        plugin = self.plugins.get(plugin_id)
        if not plugin:
            raise ValueError(f"Plugin not found: {plugin_id}")

        if plugin.status != PluginStatus.ACTIVE:
            raise ValueError(f"Plugin is not active: {plugin.metadata.name}")

        try:
            # Execute plugin
            if plugin.module:
                plugin_class = self._find_plugin_class(plugin.module)
                if plugin_class:
                    instance = plugin_class(plugin.config)
                    result = await instance.execute(**kwargs)

                    # Update usage stats
                    plugin.usage_count += 1
                    plugin.last_used = datetime.utcnow()

                    return result

            raise ValueError("Plugin has no executable module")

        except Exception as e:
            logger.error(f"Plugin execution failed: {e}")
            plugin.status = PluginStatus.ERROR
            plugin.error_message = str(e)
            raise

    # ==================== Hook System ====================

    def register_hook(
        self,
        hook_name: str,
        description: str,
        parameters: Dict[str, type],
        return_type: type
    ) -> PluginHook:
        """Register a plugin hook."""
        hook = PluginHook(
            hook_name=hook_name,
            description=description,
            parameters=parameters,
            return_type=return_type
        )

        self.hooks[hook_name] = hook
        logger.info(f"Registered hook: {hook_name}")
        return hook

    def add_hook_callback(self, hook_name: str, callback: Callable) -> bool:
        """Add a callback to a hook."""
        hook = self.hooks.get(hook_name)
        if not hook:
            logger.warning(f"Hook not found: {hook_name}")
            return False

        hook.callbacks.append(callback)
        logger.info(f"Added callback to hook: {hook_name}")
        return True

    async def execute_hook(self, hook_name: str, **kwargs) -> List[Any]:
        """Execute all callbacks for a hook."""
        hook = self.hooks.get(hook_name)
        if not hook:
            logger.warning(f"Hook not found: {hook_name}")
            return []

        results = []
        for callback in hook.callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    result = await callback(**kwargs)
                else:
                    result = callback(**kwargs)
                results.append(result)
            except Exception as e:
                logger.error(f"Hook callback failed: {e}")

        return results

    # ==================== Marketplace ====================

    def publish_listing(self, listing: MarketplaceListing) -> bool:
        """Publish a plugin to the marketplace."""
        self.listings[listing.listing_id] = listing
        logger.info(f"Published listing: {listing.plugin_metadata.name}")
        return True

    def search_marketplace(
        self,
        query: Optional[str] = None,
        category: Optional[MarketplaceCategory] = None,
        verified_only: bool = False
    ) -> List[MarketplaceListing]:
        """Search the marketplace."""
        listings = list(self.listings.values())

        if query:
            listings = [
                l for l in listings
                if query.lower() in l.plugin_metadata.name.lower() or
                   query.lower() in l.plugin_metadata.description.lower()
            ]

        if category:
            listings = [l for l in listings if l.plugin_metadata.category == category]

        if verified_only:
            listings = [l for l in listings if l.verified]

        # Sort by rating and install count
        listings.sort(key=lambda l: (l.rating, l.install_count), reverse=True)

        return listings


# Global marketplace instance
_marketplace: Optional[IntegrationMarketplace] = None


def get_marketplace() -> IntegrationMarketplace:
    """Get the global marketplace instance."""
    global _marketplace
    if _marketplace is None:
        _marketplace = IntegrationMarketplace()
    return _marketplace
