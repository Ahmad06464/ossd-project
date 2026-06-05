from database.sqlite_manager import DB
import subprocess

db = DB()

def run_subfinder(domain):
    target_id = db.add_target(domain)

    result = subprocess.run(
        ["subfinder", "-d", domain, "-silent"],
        capture_output=True,
        text=True
    )

    subdomains = result.stdout.splitlines()

    for sub in subdomains:
        db.add_subdomain(
            target_id=target_id,
            subdomain=sub,
            source="subfinder"
        )

    return subdomains