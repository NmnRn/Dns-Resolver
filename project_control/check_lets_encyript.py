"""
Let's Encrypt Certificate Checker
Specifically checks and manages Let's Encrypt SSL certificates.
"""

import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import re


class LetsEncryptChecker:
    """Check and manage Let's Encrypt certificates."""

    # Common Let's Encrypt certificate paths
    COMMON_PATHS = [
        "/etc/letsencrypt/live",
        "/etc/ssl/certs",
        "/home/*/ssl/certs",
    ]

    def __init__(self, warning_days: int = 30):
        """
        Initialize the Let's Encrypt checker.
        
        Args:
            warning_days: Number of days before expiration to warn
        """
        self.warning_days = warning_days

    def check_certificate(self, cert_path: str) -> Dict:
        """
        Check a Let's Encrypt certificate file.
        
        Args:
            cert_path: Path to the certificate file
            
        Returns:
            Dictionary with certificate information
        """
        cert_file = Path(cert_path)
        
        if not cert_file.exists():
            return {"error": f"Certificate file not found: {cert_path}"}
        
        try:
            # Get certificate info using openssl
            result = subprocess.run(
                ["openssl", "x509", "-in", str(cert_file), "-text", "-noout"],
                capture_output=True,
                text=True,
                check=True
            )
            
            cert_info = self._parse_cert_info(result.stdout, str(cert_file))
            cert_info['is_lets_encrypt'] = self._is_lets_encrypt(cert_info)
            cert_info['status'] = self._get_status(cert_info)
            cert_info['renewal_needed'] = self._check_renewal_needed(cert_info)
            
            return cert_info
            
        except subprocess.CalledProcessError as e:
            return {"error": f"Failed to read certificate: {e.stderr}"}
        except FileNotFoundError:
            return {"error": "openssl command not found"}

    def check_domain(self, domain: str) -> Dict:
        """
        Check Let's Encrypt certificate for a domain.
        
        Args:
            domain: Domain name
            
        Returns:
            Dictionary with certificate information
        """
        cert_path = f"/etc/letsencrypt/live/{domain}/fullchain.pem"
        
        if not Path(cert_path).exists():
            return {
                "error": f"Let's Encrypt certificate not found for {domain}",
                "expected_path": cert_path
            }
        
        return self.check_certificate(cert_path)

    def find_all_certificates(self) -> List[Dict]:
        """
        Find all Let's Encrypt certificates on the system.
        
        Returns:
            List of dictionaries with certificate information
        """
        certificates = []
        le_path = Path("/etc/letsencrypt/live")
        
        if not le_path.exists():
            return certificates
        
        try:
            # Iterate through domain directories
            for domain_dir in le_path.iterdir():
                if domain_dir.is_dir():
                    cert_file = domain_dir / "fullchain.pem"
                    if cert_file.exists():
                        cert_info = self.check_certificate(str(cert_file))
                        certificates.append(cert_info)
            
            # Sort by expiration date
            certificates.sort(
                key=lambda x: x.get('valid_until_dt', datetime.now())
            )
            
            return certificates
            
        except Exception as e:
            print(f"Error scanning certificates: {e}")
            return certificates

    def check_renewal_status(self) -> Dict:
        """
        Check renewal status of Let's Encrypt certificates.
        
        Returns:
            Dictionary with renewal status information
        """
        try:
            result = subprocess.run(
                ["certbot", "certificates"],
                capture_output=True,
                text=True,
                check=False
            )
            
            if result.returncode != 0:
                return {"error": "certbot not found or not installed"}
            
            return {
                "status": "success",
                "output": result.stdout,
                "certificates": self._parse_certbot_output(result.stdout)
            }
            
        except FileNotFoundError:
            return {"error": "certbot command not found. Install certbot to check renewal status."}

    def auto_renew(self, dry_run: bool = True) -> Dict:
        """
        Attempt to auto-renew Let's Encrypt certificates.
        
        Args:
            dry_run: If True, only simulate renewal without making changes
            
        Returns:
            Dictionary with renewal results
        """
        try:
            cmd = ["certbot", "renew"]
            if dry_run:
                cmd.append("--dry-run")
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            
            return {
                "success": result.returncode == 0,
                "output": result.stdout,
                "error": result.stderr if result.returncode != 0 else None,
                "dry_run": dry_run
            }
            
        except FileNotFoundError:
            return {"error": "certbot command not found"}

    def _parse_cert_info(self, cert_text: str, cert_path: str) -> Dict:
        """Parse certificate information from openssl output."""
        info = {"file_path": cert_path}
        
        lines = cert_text.split('\n')
        
        for line in lines:
            if 'Subject:' in line:
                info['subject'] = line.split('Subject:')[1].strip()
            elif 'Issuer:' in line:
                info['issuer'] = line.split('Issuer:')[1].strip()
            elif 'Not Before:' in line:
                date_str = line.split('Not Before:')[1].strip()
                info['valid_from'] = date_str
                info['valid_from_dt'] = self._parse_date(date_str)
            elif 'Not After:' in line:
                date_str = line.split('Not After:')[1].strip()
                info['valid_until'] = date_str
                info['valid_until_dt'] = self._parse_date(date_str)
            elif 'Serial Number:' in line:
                info['serial'] = line.split('Serial Number:')[1].strip()
        
        return info

    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string from certificate."""
        try:
            # Format: "Jan  1 00:00:00 2025 GMT"
            return datetime.strptime(
                date_str.replace('  ', ' '),
                '%b %d %H:%M:%S %Y %Z'
            )
        except ValueError:
            return None

    def _is_lets_encrypt(self, cert_info: Dict) -> bool:
        """Check if certificate is from Let's Encrypt."""
        issuer = cert_info.get('issuer', '').lower()
        return 'let' in issuer and 'encrypt' in issuer

    def _get_status(self, cert_info: Dict) -> str:
        """Determine certificate status."""
        if 'valid_until_dt' not in cert_info or cert_info['valid_until_dt'] is None:
            return "UNKNOWN"
        
        now = datetime.now()
        expires = cert_info['valid_until_dt']
        days_left = (expires - now).days
        
        if days_left < 0:
            return "EXPIRED"
        elif days_left < self.warning_days:
            return f"EXPIRING_SOON ({days_left} days)"
        else:
            return "VALID"

    def _check_renewal_needed(self, cert_info: Dict) -> bool:
        """Check if certificate renewal is needed."""
        if 'valid_until_dt' not in cert_info:
            return False
        
        now = datetime.now()
        expires = cert_info['valid_until_dt']
        days_left = (expires - now).days
        
        # Let's Encrypt recommends renewing 30 days before expiration
        return days_left <= 30

    def _parse_certbot_output(self, output: str) -> List[Dict]:
        """Parse certbot certificates output."""
        certificates = []
        current_cert = None
        
        for line in output.split('\n'):
            if line.startswith('-'):
                if current_cert:
                    certificates.append(current_cert)
                current_cert = {}
            elif current_cert is not None:
                if 'Certificate Name:' in line:
                    current_cert['name'] = line.split(':')[1].strip()
                elif 'Domains:' in line:
                    domains = line.split(':')[1].strip()
                    current_cert['domains'] = [d.strip() for d in domains.split(',')]
                elif 'Expiry Date:' in line:
                    current_cert['expiry'] = line.split(':')[1].strip()
        
        if current_cert:
            certificates.append(current_cert)
        
        return certificates

    def print_info(self, cert_info: Dict) -> None:
        """Print certificate information in a readable format."""
        if 'error' in cert_info:
            print(f"❌ Error: {cert_info['error']}")
            if 'expected_path' in cert_info:
                print(f"   Expected path: {cert_info['expected_path']}")
            return
        
        print("\n" + "="*60)
        print("Let's Encrypt Certificate Information")
        print("="*60)
        
        is_le = cert_info.get('is_lets_encrypt', False)
        le_symbol = "✅ Let's Encrypt" if is_le else "⚠️ Not Let's Encrypt"
        print(f"{le_symbol}")
        
        if 'file_path' in cert_info:
            print(f"File Path: {cert_info['file_path']}")
        
        if 'subject' in cert_info:
            print(f"Subject: {cert_info['subject']}")
        
        if 'issuer' in cert_info:
            print(f"Issuer: {cert_info['issuer']}")
        
        if 'valid_from' in cert_info:
            print(f"Valid From: {cert_info['valid_from']}")
        
        if 'valid_until' in cert_info:
            print(f"Valid Until: {cert_info['valid_until']}")
        
        if 'serial' in cert_info:
            print(f"Serial: {cert_info['serial']}")
        
        status = cert_info.get('status', 'UNKNOWN')
        status_symbol = "✅" if status == "VALID" else "⚠️"
        print(f"\nStatus: {status_symbol} {status}")
        
        if cert_info.get('renewal_needed'):
            print("🔄 Renewal needed: YES")
        
        print("="*60 + "\n")

    def print_all_certificates(self, certificates: List[Dict]) -> None:
        """Print all certificates in a table format."""
        if not certificates:
            print("No Let's Encrypt certificates found.")
            return
        
        print("\n" + "="*80)
        print("All Let's Encrypt Certificates")
        print("="*80)
        print(f"{'Domain':<30} {'Expires':<20} {'Days Left':<12} {'Status':<15}")
        print("-"*80)
        
        for cert in certificates:
            domain = cert.get('subject', 'Unknown')[:28]
            expires = cert.get('valid_until', 'Unknown')[:19]
            
            if 'valid_until_dt' in cert:
                days_left = (cert['valid_until_dt'] - datetime.now()).days
            else:
                days_left = -1
            
            status = cert.get('status', 'UNKNOWN')
            
            print(f"{domain:<30} {expires:<20} {days_left:<12} {status:<15}")
        
        print("="*80 + "\n")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Let's Encrypt Certificate Checker",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check specific certificate file
  python check_lets_encyript.py --check /etc/letsencrypt/live/example.com/fullchain.pem
  
  # Check certificate for domain
  python check_lets_encyript.py --domain example.com
  
  # List all Let's Encrypt certificates
  python check_lets_encyript.py --list-all
  
  # Check renewal status
  python check_lets_encyript.py --renewal-status
  
  # Dry run renewal
  python check_lets_encyript.py --renew --dry-run
        """
    )
    
    parser.add_argument(
        "--check", "-c",
        help="Check specific certificate file",
        type=str
    )
    parser.add_argument(
        "--domain", "-d",
        help="Check certificate for domain",
        type=str
    )
    parser.add_argument(
        "--list-all", "-l",
        help="List all Let's Encrypt certificates",
        action="store_true"
    )
    parser.add_argument(
        "--renewal-status", "-r",
        help="Check renewal status using certbot",
        action="store_true"
    )
    parser.add_argument(
        "--renew",
        help="Attempt to renew certificates",
        action="store_true"
    )
    parser.add_argument(
        "--dry-run",
        help="Dry run mode (no changes)",
        action="store_true"
    )
    parser.add_argument(
        "--warning-days", "-w",
        help="Days before expiration to warn (default: 30)",
        type=int,
        default=30
    )
    
    args = parser.parse_args()
    
    checker = LetsEncryptChecker(warning_days=args.warning_days)
    
    if args.check:
        cert_info = checker.check_certificate(args.check)
        checker.print_info(cert_info)
    
    elif args.domain:
        cert_info = checker.check_domain(args.domain)
        checker.print_info(cert_info)
    
    elif args.list_all:
        certificates = checker.find_all_certificates()
        checker.print_all_certificates(certificates)
    
    elif args.renewal_status:
        renewal_info = checker.check_renewal_status()
        print("\nRenewal Status:")
        for key, value in renewal_info.items():
            if key != 'certificates':
                print(f"  {key}: {value}")
    
    elif args.renew:
        result = checker.auto_renew(dry_run=args.dry_run)
        print("\nRenewal Result:")
        mode = "DRY RUN" if args.dry_run else "LIVE"
        print(f"  Mode: {mode}")
        print(f"  Success: {result.get('success', False)}")
        if result.get('output'):
            print(f"  Output: {result['output'][:200]}...")
        if result.get('error'):
            print(f"  Error: {result['error']}")
    
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
