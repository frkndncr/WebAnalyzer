import os
import subprocess

def run_subfinder(domain, logs_dir="logs"):
    """
    Runs subfinder, saves the subdomains in the logs directory, and returns the total number.
    - domain: Target domain for discovering subdomains.
    - logs_dir: Directory to save the subdomains.
    """
    try:
        # Create the logs directory if it doesn't exist
        if not os.path.exists(logs_dir):
            os.makedirs(logs_dir)

        # Check if domain directory exists inside logs
        domain_dir = os.path.join(logs_dir, domain)
        if not os.path.exists(domain_dir):
            os.makedirs(domain_dir)

        # Output file path
        output_file = os.path.join(domain_dir, f"{domain}-sub.txt")

        # Run Subfinder
        result = subprocess.run(
            ["subfinder", "-d", domain],
            capture_output=True,
            text=True,
            check=True
        )

        # Process subfinder output
        subdomains = result.stdout.splitlines()

        # Save results to the output file
        with open(output_file, "w") as file:
            file.write("\n".join(subdomains))

        print(f"Subdomains saved to: {output_file}")
        return subdomains
    except FileNotFoundError:
        print("Error: Subfinder is not installed or added to PATH.")
        return []
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to run Subfinder: {e}")
        return []