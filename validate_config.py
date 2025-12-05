"""
YAML Configuration Validator
Validates config/config.yaml syntax and structure before running the analyzer
"""

import yaml
import sys
from pathlib import Path

def validate_yaml_syntax(config_path):
    """Validate YAML syntax."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return True, config, None
    except yaml.YAMLError as e:
        return False, None, str(e)
    except FileNotFoundError:
        return False, None, f"Config file not found: {config_path}"

def validate_structure(config):
    """Validate config structure has required sections."""
    required_sections = ['volatility', 'analysis', 'yara']
    missing = []
    
    for section in required_sections:
        if section not in config:
            missing.append(section)
    
    return len(missing) == 0, missing

def validate_yara_config(config):
    """Validate YARA configuration."""
    issues = []
    
    if 'yara' in config:
        yara_cfg = config['yara']
        
        # Check if enabled
        if not yara_cfg.get('enabled', False):
            issues.append("⚠ YARA scanning is disabled")
        
        # Check rules directory
        rules_dir = yara_cfg.get('rules_dir', 'yara_rules')
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            issues.append(f"✗ YARA rules directory not found: {rules_dir}")
        else:
            # Check for rules files
            yara_files = list(rules_path.glob('*.yara')) + list(rules_path.glob('*.yar'))
            if not yara_files:
                issues.append(f"✗ No YARA rules files found in {rules_dir}")
            else:
                issues.append(f"✓ Found {len(yara_files)} YARA rules file(s)")
                
                # Check for preferred all.yara
                if (rules_path / 'all.yara').exists():
                    issues.append("✓ Using preferred rules file: all.yara")
        
        # Check timeout
        timeout = yara_cfg.get('timeout', 600)
        if timeout < 300:
            issues.append(f"⚠ YARA timeout is low ({timeout}s) - may timeout on large dumps")
    
    return issues

def main():
    """Main validation routine."""
    config_path = 'config/config.yaml'
    
    print("=" * 60)
    print("YAML Configuration Validator")
    print("=" * 60)
    print()
    
    # 1. Validate syntax
    print("1. Validating YAML syntax...")
    valid, config, error = validate_yaml_syntax(config_path)
    
    if not valid:
        print(f"   ✗ YAML Syntax Error!")
        print(f"   Error: {error}")
        print()
        print("Fix the syntax error and try again.")
        return 1
    
    print("   ✓ YAML syntax is valid")
    print()
    
    # 2. Validate structure
    print("2. Validating configuration structure...")
    valid, missing = validate_structure(config)
    
    if not valid:
        print(f"   ✗ Missing required sections: {', '.join(missing)}")
        return 1
    
    print(f"   ✓ All required sections present")
    print(f"   ✓ Loaded {len(config)} configuration sections")
    print()
    
    # 3. Validate YARA config
    print("3. Validating YARA configuration...")
    yara_issues = validate_yara_config(config)
    
    for issue in yara_issues:
        print(f"   {issue}")
    print()
    
    # 4. Summary
    print("=" * 60)
    print("Validation Summary")
    print("=" * 60)
    print("✓ YAML syntax: Valid")
    print("✓ Configuration structure: Valid")
    print(f"✓ YARA enabled: {config.get('yara', {}).get('enabled', False)}")
    print()
    print("Configuration is ready to use!")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
"""
YAML Configuration Validator
Validates config/config.yaml syntax and structure before running the analyzer
"""

import yaml
import sys
from pathlib import Path

def validate_yaml_syntax(config_path):
    """Validate YAML syntax."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return True, config, None
    except yaml.YAMLError as e:
        return False, None, str(e)
    except FileNotFoundError:
        return False, None, f"Config file not found: {config_path}"

def validate_structure(config):
    """Validate config structure has required sections."""
    required_sections = ['volatility', 'analysis', 'yara']
    missing = []
    
    for section in required_sections:
        if section not in config:
            missing.append(section)
    
    return len(missing) == 0, missing

def validate_yara_config(config):
    """Validate YARA configuration."""
    issues = []
    
    if 'yara' in config:
        yara_cfg = config['yara']
        
        # Check if enabled
        if not yara_cfg.get('enabled', False):
            issues.append("⚠ YARA scanning is disabled")
        
        # Check rules directory
        rules_dir = yara_cfg.get('rules_dir', 'yara_rules')
        rules_path = Path(rules_dir)
        
        if not rules_path.exists():
            issues.append(f"✗ YARA rules directory not found: {rules_dir}")
        else:
            # Check for rules files
            yara_files = list(rules_path.glob('*.yara')) + list(rules_path.glob('*.yar'))
            if not yara_files:
                issues.append(f"✗ No YARA rules files found in {rules_dir}")
            else:
                issues.append(f"✓ Found {len(yara_files)} YARA rules file(s)")
                
                # Check for preferred all.yara
                if (rules_path / 'all.yara').exists():
                    issues.append("✓ Using preferred rules file: all.yara")
        
        # Check timeout
        timeout = yara_cfg.get('timeout', 600)
        if timeout < 300:
            issues.append(f"⚠ YARA timeout is low ({timeout}s) - may timeout on large dumps")
    
    return issues

def main():
    """Main validation routine."""
    config_path = 'config/config.yaml'
    
    print("=" * 60)
    print("YAML Configuration Validator")
    print("=" * 60)
    print()
    
    # 1. Validate syntax
    print("1. Validating YAML syntax...")
    valid, config, error = validate_yaml_syntax(config_path)
    
    if not valid:
        print(f"   ✗ YAML Syntax Error!")
        print(f"   Error: {error}")
        print()
        print("Fix the syntax error and try again.")
        return 1
    
    print("   ✓ YAML syntax is valid")
    print()
    
    # 2. Validate structure
    print("2. Validating configuration structure...")
    valid, missing = validate_structure(config)
    
    if not valid:
        print(f"   ✗ Missing required sections: {', '.join(missing)}")
        return 1
    
    print(f"   ✓ All required sections present")
    print(f"   ✓ Loaded {len(config)} configuration sections")
    print()
    
    # 3. Validate YARA config
    print("3. Validating YARA configuration...")
    yara_issues = validate_yara_config(config)
    
    for issue in yara_issues:
        print(f"   {issue}")
    print()
    
    # 4. Summary
    print("=" * 60)
    print("Validation Summary")
    print("=" * 60)
    print("✓ YAML syntax: Valid")
    print("✓ Configuration structure: Valid")
    print(f"✓ YARA enabled: {config.get('yara', {}).get('enabled', False)}")
    print()
    print("Configuration is ready to use!")
    print()
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
