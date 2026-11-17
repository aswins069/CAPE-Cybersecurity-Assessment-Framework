"""PDF report generator using WeasyPrint."""
from __future__ import annotations

import logging
from pathlib import Path

from cape.reports.assembler import ReportData
from cape.reports.generators.base import BaseReportGenerator
from cape.reports.generators.html_gen import HTMLReportGenerator

logger = logging.getLogger(__name__)


class PDFReportGenerator(BaseReportGenerator):
    """Generates PDF report via WeasyPrint from HTML template.

    Converts the HTML report to PDF using WeasyPrint.
    Falls back gracefully if WeasyPrint is not installed.
    """

    def generate(self, report_data: ReportData, output_path: Path) -> Path:
        """Generate PDF report.

        Args:
            report_data: Assembled report data.
            output_path: Output file path (should end in .pdf).

        Returns:
            Path to generated PDF file.
        """
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # First generate HTML
        html_path = output_path.with_suffix(".html")
        html_gen = HTMLReportGenerator()
        html_gen.generate(report_data, html_path)

        try:
            from weasyprint import HTML as WP_HTML
        except ImportError as e:
            raise RuntimeError(
                "WeasyPrint is not installed in this Python environment. "
                "Install it with: pip install weasyprint (and its system "
                "libraries - see https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#installation). "
                f"HTML report is available at {html_path}"
            ) from e

        try:
            WP_HTML(filename=str(html_path)).write_pdf(str(output_path))
        except Exception as e:
            raise RuntimeError(
                f"WeasyPrint failed to render the PDF ({e}). "
                f"HTML report is available at {html_path}"
            ) from e

        # WeasyPrint can return without raising yet still not have written a
        # usable file (e.g. permission issues, disk full, sandboxed FS). Never
        # report success unless the file is actually there.
        if not output_path.exists() or output_path.stat().st_size == 0:
            raise RuntimeError(
                f"PDF write did not produce a file at {output_path} "
                f"(no exception was raised, but the file is missing or empty - "
                f"check filesystem permissions and free disk space at that path). "
                f"HTML report is available at {html_path}"
            )

        logger.info(f"PDF report generated: {output_path}")
        return output_path
