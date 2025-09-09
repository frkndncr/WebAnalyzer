#!/usr/bin/env python3
"""
WebAnalyzer v3.0 - Bulk Domain Scanner
Enhanced bulk scanning with comprehensive error handling and multiple input formats
"""

import argparse
import json
import sys
import os
from pathlib import Path
from typing import List, Dict, Any
import time

try:
    from bulk.loader import BulkDomainLoader
    from bulk.processor import BulkProcessor
    from database.db_manager import db_manager
except ImportError as e:
    print(f"Error: Missing required modules. {e}")
    print("Make sure all bulk analysis components are properly installed.")
    sys.exit(1)


class BulkScanner:
    """Main bulk scanner class with enhanced functionality"""
    
    def __init__(self):
        self.loader = BulkDomainLoader()
        
    def load_domains_from_file(self, file_path: str, job_name: str = None) -> tuple:
        """Load domains from various file formats"""
        file_path = Path(file_path)
        
        if not file_path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")
        
        if not job_name:
            job_name = f"Bulk Scan - {file_path.stem}"
        
        domains = []
        
        try:
            if file_path.suffix.lower() == '.json':
                domains = self._load_json_domains(file_path)
            elif file_path.suffix.lower() == '.txt':
                domains = self._load_txt_domains(file_path)
            elif file_path.suffix.lower() == '.csv':
                domains = self._load_csv_domains(file_path)
            else:
                # Try as text file
                domains = self._load_txt_domains(file_path)
            
            if not domains:
                raise ValueError("No domains found in file")
            
            # Create temporary file for loader
            temp_file = Path('temp_domains.txt')
            with open(temp_file, 'w', encoding='utf-8') as f:
                for domain in domains:
                    f.write(f"{domain.strip()}\n")
            
            job_id, count = self.loader.load_domains(temp_file, job_name)
            temp_file.unlink()  # Clean up temp file
            
            return job_id, count
            
        except Exception as e:
            if Path('temp_domains.txt').exists():
                Path('temp_domains.txt').unlink()
            raise e
    
    def _load_json_domains(self, file_path: Path) -> List[str]:
        """Load domains from JSON file with multiple format support"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        domains = []
        
        if isinstance(data, list):
            for item in data:
                if isinstance(item, dict):
                    # Support multiple JSON formats
                    domain = (item.get('domain_name') or 
                             item.get('domain') or 
                             item.get('url', '').replace('http://', '').replace('https://', '').split('/')[0])
                    if domain:
                        domains.append(domain)
                elif isinstance(item, str):
                    domains.append(item)
        elif isinstance(data, dict):
            # Handle single domain object or domain list in dict
            if 'domains' in data:
                domains = data['domains']
            elif 'domain_name' in data:
                domains = [data['domain_name']]
            elif 'domain' in data:
                domains = [data['domain']]
        
        return [d.strip() for d in domains if d.strip()]
    
    def _load_txt_domains(self, file_path: Path) -> List[str]:
        """Load domains from text file (one per line)"""
        with open(file_path, 'r', encoding='utf-8') as f:
            domains = [line.strip() for line in f if line.strip() and not line.startswith('#')]
        return domains
    
    def _load_csv_domains(self, file_path: Path) -> List[str]:
        """Load domains from CSV file"""
        import csv
        domains = []
        
        with open(file_path, 'r', encoding='utf-8') as f:
            # Try to detect if first row is header
            sample = f.read(1024)
            f.seek(0)
            
            sniffer = csv.Sniffer()
            has_header = sniffer.has_header(sample)
            
            reader = csv.reader(f)
            
            if has_header:
                headers = next(reader)
                # Find domain column
                domain_col = 0
                for i, header in enumerate(headers):
                    if any(keyword in header.lower() for keyword in ['domain', 'url', 'host']):
                        domain_col = i
                        break
            else:
                domain_col = 0
            
            for row in reader:
                if row and len(row) > domain_col:
                    domain = row[domain_col].strip()
                    if domain:
                        # Clean URL if needed
                        domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
                        domains.append(domain)
        
        return domains


def display_job_statistics(job_id: int):
    """Display detailed job statistics"""
    try:
        stats = db_manager.get_job_statistics(job_id)
        
        print(f"\n📊 Job #{job_id} Statistics:")
        print(f"  Total Domains: {stats['total']}")
        print(f"  Completed: {stats['completed']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Pending: {stats['total'] - stats['completed'] - stats['failed']}")
        
        if stats['total'] > 0:
            completion_rate = (stats['completed'] / stats['total']) * 100
            print(f"  Progress: {completion_rate:.1f}%")
            
            if stats['completed'] > 0:
                success_rate = (stats['completed'] / (stats['completed'] + stats['failed'])) * 100
                print(f"  Success Rate: {success_rate:.1f}%")
        
        # Get recent results
        recent_results = db_manager.get_recent_scan_results(job_id, limit=5)
        if recent_results:
            print(f"\n📋 Recent Results:")
            for result in recent_results:
                status_icon = "✅" if result['status'] == 'success' else "❌"
                print(f"    {status_icon} {result['domain']} ({result['scan_date']})")
                
    except Exception as e:
        print(f"❌ Error retrieving statistics: {e}")


def list_all_jobs():
    """List all bulk scan jobs"""
    try:
        jobs = db_manager.get_all_jobs()
        
        if not jobs:
            print("📋 No bulk scan jobs found.")
            return
        
        print("\n📋 All Bulk Scan Jobs:")
        print("  ID | Name                    | Status      | Domains | Created")
        print("  ---|-------------------------|-------------|---------|------------------")
        
        for job in jobs:
            job_id = str(job['id']).ljust(2)
            name = job['name'][:23].ljust(23)
            status = job.get('status', 'Unknown').ljust(11)
            domain_count = str(job.get('domain_count', 0)).ljust(7)
            created = job.get('created_date', 'Unknown')[:16]
            
            print(f"  {job_id} | {name} | {status} | {domain_count} | {created}")
            
    except Exception as e:
        print(f"❌ Error listing jobs: {e}")


def main():
    """Main function with comprehensive argument handling"""
    parser = argparse.ArgumentParser(
        description='WebAnalyzer v3.0 - Advanced Bulk Domain Scanner',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Load domains from JSON file
  python bulk_scan.py --load domains.json --job-name "Production Scan"
  
  # Process existing job with 10 workers
  python bulk_scan.py --job-id 123 --workers 10
  
  # Include risky modules (security analysis)
  python bulk_scan.py --job-id 123 --workers 5 --risky
  
  # Show job statistics
  python bulk_scan.py --stats 123
  
  # List all jobs
  python bulk_scan.py --list-jobs
  
  # Resume incomplete job
  python bulk_scan.py --resume 123 --workers 8
        """
    )
    
    # Main commands
    parser.add_argument('--load', type=str, metavar='FILE', 
                       help='Load domains from file (JSON, CSV, TXT)')
    parser.add_argument('--job-id', type=int, metavar='ID',
                       help='Process existing job by ID')
    parser.add_argument('--resume', type=int, metavar='ID',
                       help='Resume incomplete job by ID')
    
    # Options
    parser.add_argument('--job-name', type=str, metavar='NAME',
                       help='Custom name for the scan job')
    parser.add_argument('--workers', type=int, default=5, metavar='N',
                       help='Number of parallel workers (default: 5)')
    parser.add_argument('--risky', action='store_true',
                       help='Include risky modules (security analysis, etc.)')
    
    # Information commands
    parser.add_argument('--stats', type=int, metavar='ID',
                       help='Show statistics for job ID')
    parser.add_argument('--list-jobs', action='store_true',
                       help='List all bulk scan jobs')
    
    # Parsing and validation
    args = parser.parse_args()
    
    # Validate worker count
    if args.workers < 1 or args.workers > 50:
        print("❌ Worker count must be between 1 and 50")
        sys.exit(1)
    
    scanner = BulkScanner()
    
    try:
        if args.load:
            # Load domains from file
            print(f"🔄 Loading domains from {args.load}...")
            
            job_id, count = scanner.load_domains_from_file(
                args.load, 
                args.job_name or f"Bulk Scan - {Path(args.load).stem}"
            )
            
            print(f"✅ Job #{job_id} created successfully!")
            print(f"   Loaded {count} domains")
            print(f"   Job name: {args.job_name or f'Bulk Scan - {Path(args.load).stem}'}")
            print(f"\n🚀 To start processing:")
            print(f"   python bulk_scan.py --job-id {job_id} --workers {args.workers}")
            
            if args.risky:
                print(f"   python bulk_scan.py --job-id {job_id} --workers {args.workers} --risky")
        
        elif args.job_id or args.resume:
            # Process job
            job_id = args.job_id or args.resume
            action = "Processing" if args.job_id else "Resuming"
            
            print(f"🔄 {action} job #{job_id} with {args.workers} workers...")
            
            if args.risky:
                print("⚠️  Risky modules enabled (includes security analysis)")
            
            processor = BulkProcessor(job_id, max_workers=args.workers)
            
            # Show initial statistics
            display_job_statistics(job_id)
            print(f"\n🚀 Starting scan...")
            
            start_time = time.time()
            
            try:
                stats = processor.process_job(use_risky_modules=args.risky)
                
                elapsed_time = time.time() - start_time
                
                print(f"\n🎉 Scan completed in {elapsed_time:.1f} seconds!")
                print(f"\n📊 Final Statistics:")
                print(f"  Total Processed: {stats['total_processed']}")
                print(f"  Successful: {stats['successful']}")
                print(f"  Failed: {stats['failed']}")
                
                if stats['total_processed'] > 0:
                    success_rate = (stats['successful'] / stats['total_processed']) * 100
                    print(f"  Success Rate: {success_rate:.1f}%")
                    
                    if elapsed_time > 0:
                        rate = stats['total_processed'] / elapsed_time
                        print(f"  Processing Rate: {rate:.2f} domains/second")
                
            except KeyboardInterrupt:
                print(f"\n⏹️  Scan interrupted by user")
                print(f"   Job #{job_id} can be resumed with:")
                print(f"   python bulk_scan.py --resume {job_id} --workers {args.workers}")
                
        elif args.stats:
            # Show job statistics
            display_job_statistics(args.stats)
            
        elif args.list_jobs:
            # List all jobs
            list_all_jobs()
            
        else:
            # No valid command provided
            parser.print_help()
            print(f"\n💡 Quick start:")
            print(f"   1. Load domains: python bulk_scan.py --load domains.txt")
            print(f"   2. Process job: python bulk_scan.py --job-id [ID] --workers 10")
    
    except FileNotFoundError as e:
        print(f"❌ File error: {e}")
        sys.exit(1)
    except ValueError as e:
        print(f"❌ Data error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print(f"\n⏹️  Operation interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        print(f"   If this persists, check your configuration and dependencies.")
        sys.exit(1)


if __name__ == "__main__":
    main()