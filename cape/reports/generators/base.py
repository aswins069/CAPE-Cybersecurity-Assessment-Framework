"""Base report generator class."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from cape.reports.assembler import ReportData


class BaseReportGenerator(ABC):
    """Abstract base for report generators."""

    @abstractmethod
    def generate(self, report_data: ReportData, output_path: Path) -> Path:
        """Generate report and return output file path.

        Args:
            report_data: Assembled report data.
            output_path: Path to write output file.

        Returns:
            Path to generated file.
        """
