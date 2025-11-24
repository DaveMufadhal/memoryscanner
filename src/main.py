import argparse
from datetime import datetime

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


def main() -> None:
    print("[*] Starting Forensic Memory Analysis...")
    args = parse_args()

    # Load configuration
    print(f"[*] Loading configuration from {args.config}")
    config = load_config(args.config)

    # Initialize Volatility runner
    volcfg = config.get("volatility", {})
    vol = VolatilityRunner(volcfg.get("binary_path", "vol"))
    
    print(f"[*] Analyzing memory dump: {args.image}")

    # Get list of plugins to run
    plugins = volcfg.get("default_plugins", [
        "windows.pslist.PsList",
        "windows.netscan.NetScan",
        "windows.malfind.Malfind"
    ])

    # Run Volatility plugins
    print(f"[*] Running {len(plugins)} Volatility plugins...")
    raw_outputs = vol.run_plugins_bulk(args.image, plugins)

    # Prepare analysis result container
    analysis = AnalysisResult()
    analysis.raw_outputs = raw_outputs

    # Process analysis
    print("[*] Analyzing processes...")
    pslist_plugin = "windows.pslist.PsList"
    if pslist_plugin in raw_outputs:
        basic_process_analysis(raw_outputs[pslist_plugin], config, analysis)

    # Network analysis
    print("[*] Analyzing network connections...")
    netscan_plugin = "windows.netscan.NetScan"
    if netscan_plugin in raw_outputs:
        basic_network_analysis(raw_outputs[netscan_plugin], config, analysis)
    
    # Malware injection detection
    print("[*] Detecting code injection...")
    malfind_plugin = "windows.malfind.Malfind"
    if malfind_plugin in raw_outputs:
        analyze_malfind(raw_outputs[malfind_plugin], analysis)

    # Optional: YARA scanning
    ycfg = config.get("yara", {})
    if ycfg.get("enabled", False):
        print("[*] Running YARA scans...")
        scanner = YaraScanner(ycfg.get("rules_dir", "yara_rules"))
        # TODO: Implement YARA scanning on memory regions

    # Calculate risk level
    scoring_cfg = config.get("scoring", {})
    analysis.calculate_risk_level(scoring_cfg)
    
    # Generate summary
    generate_summary(analysis, config)

    # Initialize report generator
    print("[*] Generating forensic report...")
    rcfg = config.get("report", {})
    report_gen = ReportGenerator(
        templates_dir="templates",
        output_dir=rcfg.get("output_dir", "reports"),
    )

    # Build context for template
    context = {
        "image_path": args.image,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "analysis": analysis,
        "config": config,
    }

    # Generate markdown report
    timestamp = datetime.utcnow().strftime('%Y%m%d_%H%M%S')
    output_name = f"{args.output_prefix}_{timestamp}.md"
    md_path = report_gen.generate_markdown(
        template_name="report.md.j2",
        context=context,
        output_name=output_name,
    )

    print(f"\n[+] Analysis Complete!")
    print(f"[+] Risk Level: {analysis.risk_level}")
    print(f"[+] Risk Score: {analysis.score}")
    print(f"[+] Report generated: {md_path}")
    
    if analysis.mitre_techniques:
        print(f"[+] MITRE ATT&CK Techniques: {len(set(t['technique'] for t in analysis.mitre_techniques))}")


if __name__ == "__main__":
    main()
