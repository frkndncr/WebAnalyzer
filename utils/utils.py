import os
import json
from dataclasses import is_dataclass, asdict

def clear_terminal():
    """
    Clear the terminal screen.
    """
    os.system('cls' if os.name == 'nt' else 'clear')

def save_results_to_json(domain, results, logs_dir="logs"):
    """
    Save all analysis results to a JSON file.
    """
    # Create logs directory and domain folder
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)
    domain_dir = os.path.join(logs_dir, domain)
    if not os.path.exists(domain_dir):
        os.makedirs(domain_dir)

    # Custom encoder: if an object is a dataclass, convert it to a dict.
    # Also convert sets to lists.
    def custom_encoder(obj):
        if is_dataclass(obj):
            return asdict(obj)
        if isinstance(obj, set):
            return list(obj)
        raise TypeError(f"Object of type {obj.__class__.__name__} is not JSON serializable")

    # Save results to JSON file
    output_file = os.path.join(domain_dir, "results.json")
    with open(output_file, "w", encoding="utf-8") as json_file:
        json.dump(results, json_file, indent=4, default=custom_encoder)
    print("\n\033[92m" + "=" * 50 + "\033[0m")
    print("\033[92m[✔] Analysis results have been successfully saved!\033[0m")
    print(f"\033[94m[➤] Location:\033[0m \033[93m{output_file}\033[0m")
    print("\033[92m" + "=" * 50 + "\033[0m")

def display_banner():
    """
    Display the welcome banner for the Web Analysis Tool.
    """
    banner = """
        \033[92m
        ╔══════════════════════════════════════════════════════╗
        ║                                                      ║
        ║         Welcome to the Web Analysis Tool             ║
        ║         Analyze domains with precision and style!    ║
        ║                                                      ║
        ╠══════════════════════════════════════════════════════╣
        ║         Coder: Furkan DINCER @f3rrkan                ║
        ║         Contributor: Keyvan Arasteh @keyvanarasteh   ║
        ╚══════════════════════════════════════════════════════╝
        \033[0m
    """
    print(banner)