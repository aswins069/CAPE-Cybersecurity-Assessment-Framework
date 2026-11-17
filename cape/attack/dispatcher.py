"""Attack workflow dispatcher - routes steps to modules."""
from __future__ import annotations
import logging
logger = logging.getLogger(__name__)

class WorkflowDispatcher:
    """Dispatches workflow steps to the appropriate attack modules."""
    def dispatch(self, step_name: str, modules: dict) -> object | None:
        for name, module in modules.items():
            if name.lower() in step_name.lower():
                return module
        return None
