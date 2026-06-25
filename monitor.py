import time
import os
import sys
from database.db_manager import db_manager
from tabulate import tabulate

def monitor_job(job_id):
    """Job'ı real-time monitör et"""
    
    print(f"Starting monitor for Job #{job_id}...")
    print("Press Ctrl+C to exit")
    
    try:
        while True:
            os.system('clear' if os.name == 'posix' else 'cls')
            
            try:
                # Job bilgisi
                job_info_result = db_manager.execute_query(
                    "SELECT * FROM scan_jobs WHERE id = %s",
                    (job_id,), commit=False
                )
                
                if not job_info_result:
                    print(f"❌ Job #{job_id} not found!")
                    break
                    
                job_info = job_info_result[0]
                
                # İstatistikler
                stats = db_manager.get_job_statistics(job_id)
                
                # Son taramalar
                recent = db_manager.execute_query("""
                    SELECT domain, status, scanned_at
                    FROM domains
                    WHERE job_id = %s AND scanned_at IS NOT NULL
                    ORDER BY scanned_at DESC
                    LIMIT 10
                """, (job_id,), commit=False)
                
                # Display
                print("=" * 60)
                print(f"WebAnalyzer v3.6.2 - Job #{job_id} Monitor")
                print("=" * 60)
                
                print(f"\n📊 Job: {job_info['job_name']}")
                print(f"📊 Status: {job_info['status']}")
                
                # Progress calculation
                total = max(stats['total'], 1)
                completed = stats['completed']
                failed = stats['failed']
                pending = stats.get('pending', 0)
                
                progress = (completed + failed) / total * 100
                
                print(f"📈 Progress: {completed + failed}/{total} ({progress:.1f}%)")
                print(f"✅ Completed: {completed}")
                print(f"❌ Failed: {failed}")
                print(f"⏳ Pending: {pending}")
                
                if completed > 0:
                    success_rate = (completed / (completed + failed)) * 100
                    print(f"🎯 Success Rate: {success_rate:.1f}%")
                
                # Recent scans table
                if recent:
                    print("\n📝 Recent Scans:")
                    table_data = []
                    for r in recent:
                        domain = r['domain'][:25] + "..." if len(r['domain']) > 25 else r['domain']
                        status_icon = {
                            'completed': '✅',
                            'failed': '❌', 
                            'scanning': '🔄',
                            'pending': '⏳'
                        }.get(r['status'], '❓')
                        
                        scanned_time = str(r['scanned_at'])[:19] if r['scanned_at'] else 'N/A'
                        table_data.append([domain, f"{status_icon} {r['status']}", scanned_time])
                    
                    print(tabulate(table_data, headers=['Domain', 'Status', 'Scanned At']))
                
                # Job completion check
                if job_info['status'] in ['completed', 'failed']:
                    print(f"\n🏁 Job {job_info['status']}!")
                    break
                    
            except Exception as e:
                print(f"❌ Error fetching data: {e}")
                
            print(f"\n🔄 Last updated: {time.strftime('%H:%M:%S')}")
            print("Press Ctrl+C to exit...")
            time.sleep(5)
            
    except KeyboardInterrupt:
        print("\n👋 Monitoring stopped by user")

def list_active_jobs():
    """Aktif job'ları listele"""
    try:
        jobs = db_manager.execute_query("""
            SELECT id, job_name, status, total_domains, 
                   completed_domains, created_at
            FROM scan_jobs 
            WHERE status IN ('pending', 'running')
            ORDER BY created_at DESC
            LIMIT 10
        """, commit=False)
        
        if jobs:
            print("\n📋 Active Jobs:")
            table_data = []
            for job in jobs:
                table_data.append([
                    job['id'],
                    job['job_name'][:30],
                    job['status'],
                    job['total_domains'],
                    job.get('completed_domains', 0),
                    str(job['created_at'])[:16]
                ])
            
            print(tabulate(table_data, 
                         headers=['ID', 'Name', 'Status', 'Total', 'Completed', 'Created']))
        else:
            print("📭 No active jobs found")
            
    except Exception as e:
        print(f"❌ Error listing jobs: {e}")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        try:
            job_id = int(sys.argv[1])
            monitor_job(job_id)
        except ValueError:
            print("❌ Job ID must be a number")
        except Exception as e:
            print(f"❌ Error: {e}")
    else:
        print("Usage: python monitor.py <job_id>")
        print("\nOr check active jobs first:")
        list_active_jobs()