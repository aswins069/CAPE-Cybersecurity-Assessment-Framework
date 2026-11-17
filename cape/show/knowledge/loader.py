"""Knowledge base loader for the show engine."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Optional

import yaml

from cape.show.models import AttackPattern, OpportunityRule, ServiceRule

logger = logging.getLogger(__name__)


class KnowledgeBaseLoader:
    """Loads attack patterns, service rules, and opportunity rules from files."""

    def __init__(self, kb_dir: Optional[Path] = None) -> None:
        """Initialize with knowledge base directory."""
        if kb_dir is None:
            from cape.core.config import get_config
            kb_dir = get_config().kb_dir
        self.kb_dir = kb_dir

    def load_attack_patterns(self) -> list[AttackPattern]:
        """Load attack patterns from attack_patterns.json."""
        path = self.kb_dir / "attack_patterns.json"
        if not path.exists():
            logger.warning(f"Attack patterns file not found: {path}")
            return []
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return [AttackPattern(**item) for item in data]
        except Exception as e:
            logger.error(f"Failed to load attack patterns: {e}")
            return []

    def load_service_rules(self) -> list[ServiceRule]:
        """Load service rules from service_rules.yaml."""
        path = self.kb_dir / "service_rules.yaml"
        if not path.exists():
            logger.warning(f"Service rules file not found: {path}")
            return []
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            return [ServiceRule(**item) for item in data]
        except Exception as e:
            logger.error(f"Failed to load service rules: {e}")
            return []

    def load_opportunity_rules(self) -> list[OpportunityRule]:
        """Load opportunity rules from opportunity_rules.yaml."""
        path = self.kb_dir / "opportunity_rules.yaml"
        if not path.exists():
            logger.warning(f"Opportunity rules file not found: {path}")
            return []
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or []
            return [OpportunityRule(**item) for item in data]
        except Exception as e:
            logger.error(f"Failed to load opportunity rules: {e}")
            return []

    def load_cve_mappings(self) -> dict[str, Any]:
        """Load CVE to attack pattern mappings from cve_mappings.json."""
        path = self.kb_dir / "cve_mappings.json"
        if not path.exists():
            return {}
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.error(f"Failed to load CVE mappings: {e}")
            return {}

    def get_pattern_by_id(
        self, pattern_id: str, patterns: list[AttackPattern]
    ) -> Optional[AttackPattern]:
        """Look up an attack pattern by ID."""
        for p in patterns:
            if p.id == pattern_id:
                return p
        return None
