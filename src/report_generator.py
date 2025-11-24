
### Generator

import os
from datetime import datetime
from typing import Dict, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape


class ReportGenerator:
    """
    Generates markdown (and optionally PDF) forensic reports using Jinja2 templates.
    """

    def __init__(
        self,
        templates_dir: str = "templates",
        output_dir: str = "reports",
    ) -> None:
        self.templates_dir = templates_dir
        self.output_dir = output_dir

        # Set up Jinja2 environment for template rendering
        self.env = Environment(
            loader=FileSystemLoader(self.templates_dir),
            autoescape=select_autoescape()  # Not critical for markdown but safe
        )

        # Ensure output directory exists
        os.makedirs(self.output_dir, exist_ok=True)

    def generate_markdown(
        self,
        template_name: str,
        context: Dict[str, Any],
        output_name: str,
    ) -> str:
        """
        Render a markdown report from the given template and context.

        :param template_name: Name of the Jinja2 template file (e.g., "report.md.j2").
        :param context: Dictionary with variables used in the template.
        :param output_name: Output filename (without path), e.g. "report_001.md".
        :return: Full path to the generated markdown file.
        """
        template = self.env.get_template(template_name)
        rendered = template.render(**context)

        output_path = os.path.join(self.output_dir, output_name)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(rendered)

        return output_path

    # Optional: you can add a generate_pdf() method later that:
    #   - renders markdown to HTML
    #   - converts HTML to PDF (e.g. using WeasyPrint)
