# utils/utils.py - Utility functions for WebAnalyzer
import os
import json
import platform
from datetime import datetime
from dataclasses import is_dataclass, asdict

def clear_terminal():
    """Clear the terminal screen"""
    os.system('cls' if platform.system() == 'Windows' else 'clear')

def display_banner():
    """
    Display the welcome banner for the Web Analysis Tool.
    """
    banner = """
        \033[92m
        ╔══════════════════════════════════════════════════════╗
        ║     [-] Analysis Tool                                ║ 
        ║         Analyze domains with precision and style!    ║
        ╠══════════════════════════════════════════════════════╣
        ║         Coder: Furkan DINCER @f3rrkan                ║
        ║         Contributor: Keyvan Arasteh @keyvanarasteh   ║
        ╚══════════════════════════════════════════════════════╝
        \033[0m
    """
    print(banner)

def save_results_to_json(domain, results, output_dir="logs"):
    """
    Save analysis results to JSON file
    
    Args:
        domain (str): Domain name
        results (dict): Analysis results
        output_dir (str): Output directory
    """
    try:
        # Create domain-specific directory
        domain_dir = os.path.join(output_dir, domain)
        os.makedirs(domain_dir, exist_ok=True)
        
        # Prepare results with metadata
        output_data = {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "scan_info": {
                "total_modules": len(results),
                "successful_modules": len([r for r in results.values() if not isinstance(r, dict) or 'error' not in r]),
                "failed_modules": len([r for r in results.values() if isinstance(r, dict) and 'error' in r])
            },
            "results": serialize_results(results)
        }
        
        # Save to JSON file
        output_file = os.path.join(domain_dir, "results.json")
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"\033[92m✅ Results saved to: {output_file}\033[0m")
        
    except Exception as e:
        print(f"\033[91m❌ Error saving results: {e}\033[0m")
        raise

def serialize_results(results):
    """
    Serialize results to make them JSON compatible
    
    Args:
        results: Results dictionary
    
    Returns:
        dict: Serialized results
    """
    serialized = {}
    
    for module_name, result in results.items():
        try:
            if is_dataclass(result):
                serialized[module_name] = asdict(result)
            elif isinstance(result, dict):
                serialized[module_name] = serialize_dict(result)
            elif isinstance(result, list):
                serialized[module_name] = serialize_list(result)
            else:
                serialized[module_name] = str(result)
        except Exception as e:
            serialized[module_name] = {"error": f"Serialization failed: {str(e)}"}
    
    return serialized

def serialize_dict(data):
    """Serialize dictionary recursively"""
    if not isinstance(data, dict):
        return str(data)
    
    serialized = {}
    for key, value in data.items():
        try:
            if isinstance(value, dict):
                serialized[key] = serialize_dict(value)
            elif isinstance(value, list):
                serialized[key] = serialize_list(value)
            elif is_dataclass(value):
                serialized[key] = asdict(value)
            else:
                serialized[key] = value
        except Exception:
            serialized[key] = str(value)
    
    return serialized

def serialize_list(data):
    """Serialize list recursively"""
    if not isinstance(data, list):
        return str(data)
    
    serialized = []
    for item in data:
        try:
            if isinstance(item, dict):
                serialized.append(serialize_dict(item))
            elif isinstance(item, list):
                serialized.append(serialize_list(item))
            elif is_dataclass(item):
                serialized.append(asdict(item))
            else:
                serialized.append(item)
        except Exception:
            serialized.append(str(item))
    
    return serialized

def format_execution_time(seconds):
    """
    Format execution time in human readable format
    
    Args:
        seconds (float): Time in seconds
    
    Returns:
        str: Formatted time string
    """
    if seconds < 1:
        return f"{seconds*1000:.0f}ms"
    elif seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        minutes = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{minutes}m {secs}s"
    else:
        hours = int(seconds // 3600)
        minutes = int((seconds % 3600) // 60)
        return f"{hours}h {minutes}m"

def validate_domain(domain):
    """
    Basic domain validation
    
    Args:
        domain (str): Domain to validate
        
    Returns:
        bool: True if valid domain
    """
    import re
    
    # Basic domain pattern
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    
    if not domain or len(domain) > 253:
        return False
    
    return bool(re.match(pattern, domain))

def create_directory_structure(base_dir="logs"):
    """
    Create necessary directory structure
    
    Args:
        base_dir (str): Base directory for logs
    """
    try:
        os.makedirs(base_dir, exist_ok=True)
        print(f"📁 Created directory structure: {base_dir}")
    except Exception as e:
        print(f"❌ Error creating directories: {e}")

def print_module_header(module_name, step=None, total_steps=None):
    """
    Print formatted module header
    
    Args:
        module_name (str): Name of the module
        step (int, optional): Current step number
        total_steps (int, optional): Total number of steps
    """
    header_length = 50
    
    if step and total_steps:
        title = f"[{step}/{total_steps}] {module_name.upper()}"
    else:
        title = module_name.upper()
    
    print(f"\n\033[93m{'='*header_length}\033[0m")
    print(f"\033[93m{title:^{header_length}}\033[0m")
    print(f"\033[93m{'='*header_length}\033[0m")

def print_success(message):
    """Print success message in green"""
    print(f"\033[92m✅ {message}\033[0m")

def print_error(message):
    """Print error message in red"""
    print(f"\033[91m❌ {message}\033[0m")

def print_warning(message):
    """Print warning message in yellow"""
    print(f"\033[93m⚠️ {message}\033[0m")

def print_info(message):
    """Print info message in blue"""
    print(f"\033[94mℹ️ {message}\033[0m")

def get_file_size(file_path):
    """
    Get human readable file size
    
    Args:
        file_path (str): Path to file
        
    Returns:
        str: Formatted file size
    """
    try:
        size_bytes = os.path.getsize(file_path)
        
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024**2:
            return f"{size_bytes/1024:.1f} KB"
        elif size_bytes < 1024**3:
            return f"{size_bytes/(1024**2):.1f} MB"
        else:
            return f"{size_bytes/(1024**3):.1f} GB"
    except Exception:
        return "Unknown"

# Progress bar utility
class ProgressBar:
    """Simple progress bar for terminal"""
    
    def __init__(self, total, width=50, prefix='Progress', suffix='Complete'):
        self.total = total
        self.width = width
        self.prefix = prefix
        self.suffix = suffix
        self.current = 0
    
    def update(self, amount=1):
        """Update progress bar"""
        self.current += amount
        self.display()
    
    def display(self):
        """Display current progress"""
        percent = (self.current / self.total) * 100
        filled_length = int(self.width * self.current // self.total)
        bar = '█' * filled_length + '-' * (self.width - filled_length)
        
        print(f'\r{self.prefix} |{bar}| {percent:.1f}% {self.suffix}', end='', flush=True)
        
        if self.current >= self.total:
            print()  # New line when complete