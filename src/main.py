import argparse
from datetime import datetime, timezone
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich.panel import Panel
from rich.table import Table
from rich import box
from rich.text import Text

from .config_loader import load_config
from .volatility_runner import VolatilityRunner
from .analyzer import (
    AnalysisResult,
    basic_process_analysis,
    basic_network_analysis,
    analyze_malfind,
    generate_summary
)
from .report_generator import ReportGenerator
from .yara_scanner import YaraScanner

console = Console()


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Automated Volatile Memory Forensic Analysis using Volatility3"
    )
    parser.add_argument(
        "-i", "--image",
        required=True,
        help="Path to memory image file (e.g., .raw, .mem, .vmem)"
    )
    parser.add_argument(
        "-o", "--output-prefix",
        default="report",
        help="Prefix for the generated report file (default: report)"
    )
    parser.add_argument(
        "-c", "--config",
        default="config/config.yaml",
        help="Path to YAML config file"
    )
    return parser.parse_args()


def print_banner():
    banner = """
    ███╗   ███╗███████╗███╗   ███╗ ██████╗ ██████╗ ██╗   ██╗
    ████╗ ████║██╔════╝████╗ ████║██╔═══██╗██╔══██╗╚██╗ ██╔╝
    ██╔████╔██║█████╗  ██╔████╔██║██║   ██║██████╔╝ ╚████╔╝ 
    ██║╚██╔╝██║██╔══╝  ██║╚██╔╝██║██║   ██║██╔══██╗  ╚██╔╝  
    ██║ ╚═╝ ██║███████╗██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║   
    ╚═╝     ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   
    ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ 
    ██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗
    ███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝
    ╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗
    ███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║
    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝
    """
    console.print(banner, style="bold cyan")
    console.print("    [bold yellow]Automated Volatile Memory Forensic Analysis[/bold yellow]")
    console.print("    [dim]Powered by Volatility3[/dim]\n")


def get_risk_color(risk_level: str) -> str:
    colors = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "SAFE": "bold green"
    }
    return colors.get(risk_level.upper(), "white")


def main() -> None:
    print_banner()
    
    args = parse_args()

    # Load configuration
    with console.status("[bold blue]Loading configuration...", spinner="dots"):
        config = load_config(args.config)
    console.print(f"[green]✓[/green] Configuration loaded from [cyan]{args.config}[/cyan]")

    # Initialize Volatility runner
    volcfg = config.get("volatility", {})
    vol = VolatilityRunner(volcfg.get("binary_path", "vol"))
    
    console.print(f"\n[bold]Memory Image:[/bold] [cyan]{args.image}[/cyan]")

    # Get list of plugins to run
    plugins = volcfg.get("default_plugins", [
        "windows.pslist.PsList",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind"
    ])

    # Run Volatility plugins with progress bar
    console.print(f"\n[bold magenta]Running {len(plugins)} Volatility plugins...[/bold magenta]")
    
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("[cyan]Executing plugins...", total=len(plugins))
        raw_outputs = {}
        for plugin in plugins:
            progress.update(task, description=f"[cyan]Running {plugin.split('.')[-1]}...")
            result = vol.run_plugins_bulk(args.image, [plugin])
            raw_outputs.update(result)
            progress.advance(task)

    console.print("[green]✓[/green] All plugins executed successfully\n")

    # Prepare analysis result container
    analysis = AnalysisResult()
    analysis.raw_outputs = raw_outputs

    # Process analysis
    console.print("[bold blue]┌─ Process Analysis[/bold blue]")
    with console.status("  [dim]Analyzing processes...", spinner="dots"):
        pslist_plugin = "windows.pslist.PsList"
        if pslist_plugin in raw_outputs:
            basic_process_analysis(raw_outputs[pslist_plugin], config, analysis)
    console.print("[green]  ✓[/green] Process analysis complete")

    # Network analysis
    console.print("[bold blue]├─ Network Analysis[/bold blue]")
    with console.status("  [dim]Analyzing network connections...", spinner="dots"):
        netscan_plugin = "windows.netscan.NetScan"
        if netscan_plugin in raw_outputs:
            basic_network_analysis(raw_outputs[netscan_plugin], config, analysis)
    console.print("[green]  ✓[/green] Network analysis complete")
    
    # Malware injection detection
    console.print("[bold blue]├─ Malware Detection[/bold blue]")
    with console.status("  [dim]Detecting code injection...", spinner="dots"):
        malfind_plugin = "windows.malfind.Malfind"
        if malfind_plugin in raw_outputs:
            analyze_malfind(raw_outputs[malfind_plugin], analysis, config)
    console.print("[green]  ✓[/green] Malware detection complete")

    # Optional: YARA scanning
    ycfg = config.get("yara", {})
    if ycfg.get("enabled", False):
        console.print("[bold blue]├─ YARA Scanning[/bold blue]")
        with console.status("  [dim]Running YARA scans...", spinner="dots"):
            scanner = YaraScanner(ycfg.get("rules_dir", "yara_rules"))
            # TODO: Implement YARA scanning on memory regions
        console.print("[green]  ✓[/green] YARA scanning complete")

    # Calculate risk level
    console.print("[bold blue]└─ Risk Assessment[/bold blue]")
    with console.status("  [dim]Calculating risk level...", spinner="dots"):
        scoring_cfg = config.get("scoring", {})
        analysis.calculate_risk_level(scoring_cfg)
        generate_summary(analysis, config)
    console.print("[green]  ✓[/green] Risk assessment complete\n")

    # Initialize report generator
    with console.status("[bold blue]Generating forensic report...", spinner="dots"):
        rcfg = config.get("report", {})
        report_gen = ReportGenerator(
            templates_dir="templates",
            output_dir=rcfg.get("output_dir", "reports"),
        )

        # Build context for template
        context = {
            "image_path": args.image,
            "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "analysis": analysis,
            "config": config,
        }

        # Generate markdown report
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        output_name = f"{args.output_prefix}_{timestamp}.md"
        md_path = report_gen.generate_markdown(
            template_name="report.md.j2",
            context=context,
            output_name=output_name,
        )

    # Create results table
    table = Table(title="Analysis Results", box=box.ROUNDED, show_header=True, header_style="bold magenta")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Value", style="white")
    
    risk_color = get_risk_color(analysis.risk_level)
    table.add_row("Risk Level", f"[{risk_color}]{analysis.risk_level}[/{risk_color}]")
    table.add_row("Risk Score", f"[bold]{analysis.score}[/bold]")
    
    if analysis.mitre_techniques:
        mitre_count = len(set(t['technique'] for t in analysis.mitre_techniques))
        table.add_row("MITRE ATT&CK Techniques", f"[yellow]{mitre_count}[/yellow]")
    
    table.add_row("Report Location", f"[green]{md_path}[/green]")
    
    console.print("\n")
    console.print(table)
    
    # Final success message
    panel = Panel(
        f"[bold green]✓ Analysis Complete![/bold green]\n\n"
        f"Your forensic report has been generated successfully.\n"
        f"Review the report at: [cyan]{md_path}[/cyan]",
        title="[bold]Success[/bold]",
        border_style="green",
        padding=(1, 2)
    )
    console.print("\n", panel)


if __name__ == "__main__":
    main()
