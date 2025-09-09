from database.db_manager import db_manager
from tabulate import tabulate

def check_progress():
    # Tüm job'ları listele
    jobs = db_manager.execute_query("""
        SELECT id, job_name, total_domains, completed_domains, status, created_at
        FROM scan_jobs
        ORDER BY id DESC
    """, commit=False)
    
    print("\n📋 All Jobs:")
    if jobs:
        table_data = [
            [j['id'], j['job_name'][:30], j['total_domains'], 
             j['completed_domains'], j['status'], j['created_at']]
            for j in jobs
        ]
        print(tabulate(table_data, 
                      headers=['ID', 'Name', 'Total', 'Done', 'Status', 'Created'],
                      tablefmt='grid'))
    
    # Son job'ın detayları
    if jobs:
        latest_job = jobs[0]['id']
        stats = db_manager.get_job_statistics(latest_job)
        
        print(f"\n📊 Job #{latest_job} Statistics:")
        print(f"  Total: {stats['total']}")
        print(f"  Completed: {stats['completed']}")
        print(f"  Failed: {stats['failed']}")
        print(f"  Progress: {(stats['completed']/max(stats['total'],1)*100):.1f}%")
        
        # Risk dağılımı
        risk_dist = db_manager.execute_query("""
            SELECT risk_level, COUNT(*) as count
            FROM scan_results
            WHERE domain_id IN (SELECT id FROM domains WHERE job_id = %s)
            GROUP BY risk_level
        """, (latest_job,), commit=False)
        
        if risk_dist:
            print("\n⚠️  Risk Distribution:")
            for r in risk_dist:
                print(f"  {r['risk_level']}: {r['count']}")

if __name__ == "__main__":
    check_progress()