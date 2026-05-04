"""
ShadowNet — OSINT Module Base & Registry
Abstract interface that all OSINT modules must implement.
"""

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass
class EntityFound:
    """A single entity discovered by an OSINT module."""
    entity_type: str          # person, email, domain, ip, username, etc.
    value: str
    source: str               # module that found it
    confidence: float = 0.8   # 0.0 - 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    relationships: List[Dict[str, str]] = field(default_factory=list)


@dataclass
class ScanResult:
    """Standardized output from any OSINT module."""
    module: str
    target: str
    success: bool
    entities: List[EntityFound] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    summary: str = ""
    severity: str = "info"     # critical, high, medium, low, info
    error: Optional[str] = None
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class OSINTModule(ABC):
    """
    Abstract base class for all OSINT modules.
    Every module must implement scan() and declare its metadata.
    """

    # Module metadata — override in subclasses
    name: str = "base"
    description: str = ""
    supported_target_types: List[str] = []   # e.g. ["email", "domain"]
    requires_api_key: bool = False
    rate_limit: int = 0                       # max requests per minute, 0 = unlimited

    @abstractmethod
    async def scan(self, target: str, options: Dict[str, Any] = None) -> ScanResult:
        """
        Run the OSINT scan against the target.
        Must return a ScanResult with discovered entities.
        """
        pass

    async def enrich(self, entity: EntityFound) -> List[EntityFound]:
        """
        Optional: enrich an existing entity with additional data.
        Override in modules that support enrichment.
        """
        return []

    def get_info(self) -> dict:
        """Return module metadata."""
        return {
            "name": self.name,
            "description": self.description,
            "supported_target_types": self.supported_target_types,
            "requires_api_key": self.requires_api_key,
        }


class ModuleRegistry:
    """
    Central registry for all OSINT modules.
    Modules register themselves on import.
    """
    _modules: Dict[str, OSINTModule] = {}

    @classmethod
    def register(cls, module: OSINTModule):
        """Register a module instance."""
        cls._modules[module.name] = module

    @classmethod
    def get(cls, name: str) -> Optional[OSINTModule]:
        """Get a module by name."""
        return cls._modules.get(name)

    @classmethod
    def get_modules_for_type(cls, target_type: str) -> List[str]:
        """Get all module names that support a given target type."""
        return [
            name for name, mod in cls._modules.items()
            if target_type in mod.supported_target_types
        ]

    @classmethod
    def get_all(cls) -> Dict[str, OSINTModule]:
        """Get all registered modules."""
        return cls._modules.copy()

    @classmethod
    def list_names(cls) -> List[str]:
        """Get all module names."""
        return list(cls._modules.keys())

    @classmethod
    def list_all(cls) -> List[dict]:
        """List all registered modules."""
        return [mod.get_info() for mod in cls._modules.values()]

    @classmethod
    def list_free(cls) -> List[dict]:
        """List only modules that don't require API keys."""
        return [
            mod.get_info() for mod in cls._modules.values()
            if not mod.requires_api_key
        ]
