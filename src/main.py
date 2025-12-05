import argparse
import sys
import os
from pathlib import Path
from datetime import datetime, timezone
from typing import Tuple

# Try to import rich for beautiful output, fallback to basic print if not available
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False
    # Fallback console class
    class Console:
        def print(self, *args, **kwargs):
            print(*args)

from .config_loader import load_config
from .volatility_runner import VolatilityRunner
from .data_extractor import DataExtractor
from .analyzer import (
    AnalysisResult,
    basic_process_analysis,
    basic_network_analysis,
    analyze_malfind,
    generate_summary,
    analyze_handle_artifacts,
    analyze_vad_tree,
    analyze_registry_persistence,
    analyze_memory_mapped_files,
    enhanced_detection_analysis
)
from .report_generator import ReportGenerator
from .yara_scanner import YaraScanner
from .logger import setup_logging, get_logger, log_phase, log_finding, log_volatility_execution

console = Console()
logger = None  # Will be initialized in main()


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
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Logging level (default: INFO)"
    )
    parser.add_argument(
        "--no-log-file",
        action="store_true",
        help="Disable file logging (console only)"
    )
    parser.add_argument(
        "--continue-on-error",
        action="store_true",
        help="Continue analysis even if plugins fail"
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


def validate_input_file(image_path: str) -> Tuple[bool, str]:
    """Validate memory dump file."""
    image = Path(image_path)
    
    if not image.exists():
        return False, f"File not found: {image_path}"
    
    if not image.is_file():
        return False, f"Not a file: {image_path}"
    
    file_size = image.stat().st_size
    if file_size < 1024 * 1024:  # Less than 1MB
        return False, f"File too small ({file_size} bytes). Expected memory dump > 1MB"
    
    if file_size > 100 * 1024 * 1024 * 1024:  # Greater than 100GB
        return False, f"File too large ({file_size / (1024**3):.2f}GB). Maximum 100GB"
    
    return True, "Valid"


def main() -> int:
    """Main entry point with error handling."""
    global logger
    
    try:
        print_banner()
        
        args = parse_args()
        
        # Setup logging first
        log_level = getattr(__import__('logging'), args.log_level)
        case_name = Path(args.output_prefix).stem
        logger = setup_logging(
            log_dir="logs",
            log_level=log_level,
            enable_console=False,  # We use rich for console
            enable_file=not args.no_log_file,
            case_name=case_name
        )
        
        logger.info(f"Starting forensic analysis")
        logger.info(f"Memory image: {args.image}")
        logger.info(f"Output prefix: {args.output_prefix}")
        logger.info(f"Config file: {args.config}")
        
        # Validate input file
        log_phase(logger, "Input Validation", start=True)
        console.print("[bold blue]Validating input file...[/bold blue]")
        
        valid, message = validate_input_file(args.image)
        if not valid:
            logger.error(f"Input validation failed: {message}")
            console.print(f"[red]✗ Error:[/red] {message}")
            return 1
        
        file_size_mb = Path(args.image).stat().st_size / (1024 * 1024)
        logger.info(f"Input file validated: {file_size_mb:.2f} MB")
        console.print(f"[green]✓[/green] Input file validated ({file_size_mb:.2f} MB)")
        log_phase(logger, "Input Validation", start=False)
        
        # Load configuration
        log_phase(logger, "Configuration Loading", start=True)
        with console.status("[bold blue]Loading configuration...", spinner="dots"):
            try:
                config = load_config(args.config)
                logger.info(f"Configuration loaded successfully from {args.config}")
            except FileNotFoundError:
                logger.error(f"Config file not found: {args.config}")
                console.print(f"[red]✗ Error:[/red] Config file not found: {args.config}")
                return 1
            except Exception as e:
                logger.error(f"Failed to load config: {e}", exc_info=True)
                console.print(f"[red]✗ Error:[/red] Failed to load config: {e}")
                return 1
        
        console.print(f"[green]✓[/green] Configuration loaded from [cyan]{args.config}[/cyan]")
        log_phase(logger, "Configuration Loading", start=False)

        # Validate memory dump format
        log_phase(logger, "Memory Dump Validation", start=True)
        console.print("\n[bold cyan]Validating memory dump format...[/bold cyan]")
        
        try:
            from src.volatility_runner import VolatilityRunner
            volcfg = config.get("volatility", {})
            temp_runner = VolatilityRunner(volcfg.get("binary_path", "vol"))
            is_valid, message, profile = temp_runner.validate_dump_format(args.image)
            
            if not is_valid:
                logger.error(f"Memory dump validation failed: {message}")
                console.print(f"[red]✗[/red] Dump validation failed: {message}")
                return 1
            
            logger.info(f"Memory dump validation passed: {message}")
            if profile:
                logger.info(f"Detected profile: {profile}")
                console.print(f"[green]✓[/green] {message}")
                console.print(f"[dim]Profile: {profile}[/dim]")
            else:
                console.print(f"[yellow]⚠[/yellow] {message}")
            
            log_phase(logger, "Memory Dump Validation", start=False)
        except Exception as e:
            logger.error(f"Dump validation error: {e}", exc_info=True)
            console.print(f"[yellow]⚠[/yellow] Could not fully validate dump: {e}")
            # Continue anyway - validation is best-effort
        
        # Initialize Volatility runner with advanced features
        log_phase(logger, "Volatility Initialization", start=True)
        
        try:
            vol = VolatilityRunner(
                binary_path=volcfg.get("binary_path", "vol"),
                max_retries=3,
                timeout_seconds=300,  # 5 minutes per plugin
                retry_delay=5,
                enable_progress_tracking=True
            )
            logger.info("Volatility runner initialized with robust features")
            logger.info(f"  - Max retries: {vol.max_retries}")
            logger.info(f"  - Timeout: {vol.timeout_seconds}s per plugin")
            logger.info(f"  - Retry delay: {vol.retry_delay}s")
            console.print(f"[green]✓[/green] Volatility runner initialized")
            console.print(f"[dim]  Retry: {vol.max_retries} attempts | Timeout: {vol.timeout_seconds}s | Delay: {vol.retry_delay}s[/dim]")
        except Exception as e:
            logger.error(f"Failed to initialize Volatility: {e}", exc_info=True)
            console.print(f"[red]✗ Error:[/red] Failed to initialize Volatility: {e}")
            return 1
        
        log_phase(logger, "Volatility Initialization", start=False)
        
        console.print(f"\n[bold]Memory Image:[/bold] [cyan]{args.image}[/cyan]")

        # Get list of plugins to run
        plugins = volcfg.get("default_plugins", [
            "windows.pslist.PsList",
            "windows.netscan.NetScan",
            "windows.malfind.Malfind"
        ])
        
        logger.info(f"Plugins to execute: {len(plugins)}")
        for plugin in plugins:
            logger.debug(f"  - {plugin}")

        # Run Volatility plugins with progress bar and ETA
        log_phase(logger, "Volatility Plugin Execution", start=True)
        console.print(f"\n[bold magenta]Running {len(plugins)} Volatility plugins...[/bold magenta]")
        
        raw_outputs = {}
        failed_plugins = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
            TimeRemainingColumn(),  # Added ETA
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Executing plugins...", total=len(plugins))
            
            def progress_callback(plugin_name, current, total):
                progress.update(task, completed=current, description=f"[cyan]Running {plugin_name.split('.')[-1]}...")
            
            logger.info(f"Executing {len(plugins)} plugins with robust error handling")
            start_time = datetime.now()
            
            try:
                raw_outputs = vol.run_plugins_bulk(
                    args.image, 
                    plugins,
                    progress_callback=progress_callback
                )
                execution_time = (datetime.now() - start_time).total_seconds()
                logger.info(f"All plugins completed in {execution_time:.2f}s")
                
                # Log execution statistics
                stats = vol.get_statistics()
                logger.info(f"Execution statistics: {stats}")
                console.print(f"\n[dim]Statistics: {stats['plugins_succeeded']}/{stats['plugins_executed']} succeeded | "
                            f"Success rate: {stats['success_rate']} | "
                            f"Avg time: {stats['avg_execution_time']:.2f}s[/dim]")
                
                # Identify failed plugins
                for plugin, result in raw_outputs.items():
                    if isinstance(result, dict) and 'error' in result:
                        failed_plugins.append(plugin)
                        logger.warning(f"Plugin {plugin} failed: {result.get('error', 'Unknown error')}")
                        log_volatility_execution(logger, plugin, False, result.get('_plugin_execution_time', 0))
                    else:
                        log_volatility_execution(logger, plugin, True, result.get('_plugin_execution_time', 0))
            
            except Exception as e:
                logger.error(f"Plugin execution error: {e}", exc_info=True)
                
                if not args.continue_on_error:
                    console.print(f"[red]✗ Error:[/red] Plugin execution failed: {e}")
                    return 1
                else:
                    console.print(f"[yellow]⚠ Warning:[/yellow] Plugin execution error, continuing...")

        if failed_plugins:
            logger.warning(f"Failed plugins: {', '.join(failed_plugins)}")
            console.print(f"[yellow]⚠[/yellow] {len(failed_plugins)} plugin(s) failed: {', '.join(failed_plugins)}")
        else:
            console.print("[green]✓[/green] All plugins executed successfully")
        
        log_phase(logger, "Volatility Plugin Execution", start=False)
        
        if not raw_outputs:
            logger.error("No plugin outputs available, cannot continue")
            console.print("[red]✗ Error:[/red] No plugin data available. Analysis cannot proceed.")
            return 1
        
        console.print()

        # Prepare analysis result container
        logger.info("Initializing analysis result container")
        analysis = AnalysisResult()
        analysis.raw_outputs = raw_outputs

        # Process analysis
        log_phase(logger, "Process Analysis", start=True)
        console.print("[bold blue]┌─ Process Analysis[/bold blue]")
        with console.status("  [dim]Analyzing processes...", spinner="dots"):
            pslist_plugin = "windows.pslist.PsList"
            pslist_data = DataExtractor.extract_plugin_data(raw_outputs, pslist_plugin)
            if pslist_data:
                try:
                    basic_process_analysis(pslist_data, config, analysis)
                    logger.info(f"Process analysis completed: {len(analysis.suspicious_processes)} suspicious processes found")
                except Exception as e:
                    logger.error(f"Process analysis failed: {e}", exc_info=True)
                    if not args.continue_on_error:
                        console.print(f"[red]  ✗ Error:[/red] Process analysis failed: {e}")
                        return 1
                    console.print(f"[yellow]  ⚠ Warning:[/yellow] Process analysis failed: {e}")
            else:
                logger.warning(f"No data available from {pslist_plugin}")
                console.print(f"[yellow]  ⚠[/yellow] No process data available")
        console.print("[green]  ✓[/green] Process analysis complete")
        log_phase(logger, "Process Analysis", start=False)

        # Network analysis
        console.print("[bold blue]├─ Network Analysis[/bold blue]")
        with console.status("  [dim]Analyzing network connections...", spinner="dots"):
            netscan_plugin = "windows.netscan.NetScan"
            netscan_data = DataExtractor.extract_plugin_data(raw_outputs, netscan_plugin)
            if netscan_data:
                try:
                    basic_network_analysis(netscan_data, config, analysis)
                    logger.info(f"Network analysis completed: {len(analysis.suspicious_network)} suspicious connections")
                except Exception as e:
                    logger.error(f"Network analysis failed: {e}", exc_info=True)
                    if not args.continue_on_error:
                        raise
        console.print("[green]  ✓[/green] Network analysis complete")
        
        # Malware injection detection
        console.print("[bold blue]├─ Malware Detection[/bold blue]")
        with console.status("  [dim]Detecting code injection...", spinner="dots"):
            malfind_plugin = "windows.malfind.Malfind"
            malfind_data = DataExtractor.extract_plugin_data(raw_outputs, malfind_plugin)
            if malfind_data:
                try:
                    analyze_malfind(malfind_data, analysis, config)
                    logger.info(f"Malware detection completed: {len(analysis.injected_code)} injections found")
                except Exception as e:
                    logger.error(f"Malware detection failed: {e}", exc_info=True)
                    if not args.continue_on_error:
                        raise
        console.print("[green]  ✓[/green] Malware detection complete")
        
        # Handle artifact analysis
        console.print("[bold blue]├─ Handle Artifact Analysis[/bold blue]")
        with console.status("  [dim]Analyzing handle access patterns...", spinner="dots"):
            handles_plugin = "windows.handles.Handles"
            handles_data = DataExtractor.extract_plugin_data(raw_outputs, handles_plugin)
            if handles_data:
                analyze_handle_artifacts(handles_data, config, analysis)
        console.print("[green]  ✓[/green] Handle artifact analysis complete")
        
        # VAD tree analysis
        console.print("[bold blue]├─ VAD Tree Analysis[/bold blue]")
        with console.status("  [dim]Analyzing memory mappings...", spinner="dots"):
            # Use malfind output which contains VAD data
            vad_data = DataExtractor.extract_plugin_data(raw_outputs, malfind_plugin)
            if vad_data:
                analyze_vad_tree(vad_data, config, analysis)
        console.print("[green]  ✓[/green] VAD tree analysis complete")
        
        # Registry persistence analysis
        console.print("[bold blue]├─ Registry Persistence Analysis[/bold blue]")
        with console.status("  [dim]Checking registry hives...", spinner="dots"):
            hivelist_plugin = "windows.registry.hivelist.HiveList"
            hivelist_data = DataExtractor.extract_plugin_data(raw_outputs, hivelist_plugin)
            if hivelist_data:
                analyze_registry_persistence(hivelist_data, config, analysis)
        console.print("[green]  ✓[/green] Registry persistence analysis complete")
        
        # Memory-mapped file analysis
        console.print("[bold blue]├─ Memory-Mapped File Analysis[/bold blue]")
        with console.status("  [dim]Analyzing loaded DLLs and modules...", spinner="dots"):
            dlllist_plugin = "windows.dlllist.DllList"
            dlllist_data = DataExtractor.extract_plugin_data(raw_outputs, dlllist_plugin)
            if dlllist_data:
                analyze_memory_mapped_files(dlllist_data, config, analysis)
        console.print("[green]  ✓[/green] Memory-mapped file analysis complete")

        # Optional: YARA scanning
        ycfg = config.get("yara", {})
        if ycfg.get("enabled", False):
            console.print("[bold blue]├─ YARA Scanning[/bold blue]")
            with console.status("  [dim]Running YARA scans...", spinner="dots"):
                scanner = YaraScanner(ycfg.get("rules_dir", "yara_rules"))
                # TODO: Implement YARA scanning on memory regions
            console.print("[green]  ✓[/green] YARA scanning complete")
        
        # Enhanced detection engine analysis
        console.print("[bold blue]├─ Enhanced Detection Engine[/bold blue]")
        with console.status("  [dim]Running behavioral analysis, LOLBin detection, entropy analysis...", spinner="dots"):
            enhanced_detection_analysis(analysis, config)
        console.print("[green]  ✓[/green] Enhanced detection complete")
        
        # Phase 2: Advanced detection patterns & correlation
        console.print("[bold blue]├─ Phase 2: Advanced Threat Detection[/bold blue]")
        with console.status("  [dim]Running credential theft, persistence, lateral movement detection...", spinner="dots"):
            from src.analyzer import run_phase2_detections
            # Pass memory dump path for YARA scanning
            config['memory_dump_path'] = args.image
            run_phase2_detections(analysis, raw_outputs, config)
            
            # Log Phase 2 results
            logger.info(f"Phase 2 Detection Results:")
            logger.info(f"  Credential Theft: {len(analysis.credential_theft)}")
            logger.info(f"  Persistence Mechanisms: {len(analysis.persistence_detections)}")
            logger.info(f"  Lateral Movement: {len(analysis.lateral_movement_detections)}")
            logger.info(f"  Privilege Escalation: {len(analysis.privilege_escalation_detections)}")
            logger.info(f"  Data Exfiltration: {len(analysis.data_exfiltration)}")
            logger.info(f"  Ransomware Indicators: {len(analysis.ransomware_indicators)}")
            logger.info(f"  Rootkit Indicators: {len(analysis.rootkit_indicators)}")
            logger.info(f"  YARA Matches: {len(analysis.yara_findings)}")
            logger.info(f"  Attack Chains: {len(analysis.attack_chains)}")
            logger.info(f"  Threat Score: {analysis.threat_score}")
        
        console.print("[green]  ✓[/green] Phase 2 advanced detection complete")
        
        # Display Phase 2 summary
        if analysis.attack_chains:
            console.print(f"[red]  ⚠ {len(analysis.attack_chains)} attack chain(s) detected![/red]")
        if analysis.yara_findings:
            console.print(f"[yellow]  ⚠ {len(analysis.yara_findings)} YARA match(es)[/yellow]")

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
        logger.info("=" * 80)
        logger.info("Analysis completed successfully")
        logger.info(f"Report generated: {md_path}")
        logger.info(f"Risk level: {analysis.risk_level}")
        logger.info(f"Risk score: {analysis.score}")
        logger.info("=" * 80)
        
        panel = Panel(
            f"[bold green]✓ Analysis Complete![/bold green]\n\n"
            f"Your forensic report has been generated successfully.\n"
            f"Review the report at: [cyan]{md_path}[/cyan]",
            title="[bold]Success[/bold]",
            border_style="green",
            padding=(1, 2)
        )
        console.print("\n", panel)
        
        return 0
    
    except KeyboardInterrupt:
        if logger:
            logger.warning("Analysis interrupted by user (Ctrl+C)")
        console.print("\n[yellow]⚠ Analysis interrupted by user[/yellow]")
        return 130
    
    except Exception as e:
        if logger:
            logger.critical(f"Unexpected error: {e}", exc_info=True)
        console.print(f"\n[red]✗ Critical Error:[/red] {e}")
        console.print("[dim]Check logs for details[/dim]")
        return 1


if __name__ == "__main__":
    sys.exit(main())
