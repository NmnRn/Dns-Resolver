"""
SSL Certificate Verification Tool
Checks SSL/TLS certificates for validity, expiration dates, and other details.
"""

import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path
import subprocess
import sys
from typing import Dict, Tuple, Optional


class SSLCertificateChecker:
    """Check and verify SSL certificates."""

    def __init__(self, warning_days: int = 30):
        """
        Initialize the certificate checker.
        
        Args:
            warning_days: Number of days before expiration to warn (default: 30)
        """
        self.warning_days = warning_days

    def check_file(self, cert_path: str) -> Dict:
        """
        Check a local certificate file.
        
        Args:
            cert_path: Path to the certificate file (.pem, .crt, etc.)
            
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
            
            cert_info = self._parse_cert_info(result.stdout)
            cert_info['file_path'] = str(cert_file)
            cert_info['status'] = self._get_status(cert_info)
            
            return cert_info
            
        except subprocess.CalledProcessError as e:
            return {"error": f"Failed to read certificate: {e.stderr}"}
        except FileNotFoundError:
            return {"error": "openssl command not found. Please install OpenSSL."}

    def check_domain(self, hostname: str, port: int = 443) -> Dict:
        """
        Check SSL certificate from a remote server.
        
        Args:
            hostname: Domain name or IP address
            port: Port number (default: 443)
            
        Returns:
            Dictionary with certificate information
        """
        try:
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    der_cert = ssock.getpeercert(binary_form=True)
                    
                    # Get certificate using openssl
                    cert_pem = ssl.DER_cert_to_PEM_cert(der_cert)
                    
                    cert_info = self._parse_cert_dict(cert)
                    cert_info['hostname'] = hostname
                    cert_info['port'] = port
                    cert_info['status'] = self._get_status(cert_info)
                    
                    return cert_info
                    
        except socket.timeout:
            return {"error": f"Connection timeout to {hostname}:{port}"}
        except socket.gaierror:
            return {"error": f"Could not resolve hostname: {hostname}"}
        except ssl.SSLError as e:
            return {"error": f"SSL error: {str(e)}"}
        except Exception as e:
            return {"error": f"Error checking certificate: {str(e)}"}

    def _parse_cert_info(self, cert_text: str) -> Dict:
        """Parse certificate information from openssl output."""
        info = {}
        
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
            elif 'Public-Key:' in line:
                key_info = line.split('Public-Key:')[1].strip()
                info['key_type'] = key_info
            elif 'X509v3 Subject Alternative Name:' in line:
                info['has_san'] = True
        
        return info

    def _parse_cert_dict(self, cert: Dict) -> Dict:
        """Parse certificate dictionary from ssl module."""
        info = {}
        
        if 'subject' in cert:
            subject_parts = [part[0][1] for part in cert['subject']]
            info['subject'] = ', '.join(subject_parts)
        
        if 'issuer' in cert:
            issuer_parts = [part[0][1] for part in cert['issuer']]
            info['issuer'] = ', '.join(issuer_parts)
        
        if 'notBefore' in cert:
            info['valid_from'] = cert['notBefore']
        
        if 'notAfter' in cert:
            info['valid_until'] = cert['notAfter']
            info['valid_until_dt'] = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
        
        if 'subjectAltName' in cert:
            san_list = [name[1] for name in cert['subjectAltName']]
            info['san'] = san_list
        
        return info

    def _parse_date(self, date_str: str) -> datetime:
        """Parse date string from certificate."""
        try:
            # Format: "Jan  1 00:00:00 2025 GMT"
            return datetime.strptime(date_str.replace('  ', ' '), '%b %d %H:%M:%S %Y %Z')
        except ValueError:
            return None

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

    def print_info(self, cert_info: Dict) -> None:
        """Print certificate information in a readable format."""
        if 'error' in cert_info:
            print(f"❌ Error: {cert_info['error']}")
            return
        
        print("\n" + "="*60)
        print("SSL Certificate Information")
        print("="*60)
        
        if 'file_path' in cert_info:
            print(f"File Path: {cert_info['file_path']}")
        
        if 'hostname' in cert_info:
            print(f"Hostname: {cert_info['hostname']}:{cert_info.get('port', 443)}")
        
        if 'subject' in cert_info:
            print(f"Subject: {cert_info['subject']}")
        
        if 'issuer' in cert_info:
            print(f"Issuer: {cert_info['issuer']}")
        
        if 'valid_from' in cert_info:
            print(f"Valid From: {cert_info['valid_from']}")
        
        if 'valid_until' in cert_info:
            print(f"Valid Until: {cert_info['valid_until']}")
        
        if 'san' in cert_info:
            print(f"Subject Alternative Names: {', '.join(cert_info['san'])}")
        
        if 'key_type' in cert_info:
            print(f"Key Type: {cert_info['key_type']}")
        
        status = cert_info.get('status', 'UNKNOWN')
        status_symbol = "✅" if status == "VALID" else "⚠️" if "EXPIRING" in status else "❌"
        print(f"\nStatus: {status_symbol} {status}")
        print("="*60 + "\n")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="SSL Certificate Verification Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check local certificate file
  python check_ssl_certificate.py --file /path/to/cert.pem
  
  # Check remote domain
  python check_ssl_certificate.py --domain example.com
  
  # Check with custom warning days
  python check_ssl_certificate.py --file cert.pem --warning-days 60
        """
    )
    
    parser.add_argument(
        "--file", "-f",
        help="Path to certificate file",
        type=str
    )
    parser.add_argument(
        "--domain", "-d",
        help="Domain name or IP address to check",
        type=str
    )
    parser.add_argument(
        "--port", "-p",
        help="Port number for remote check (default: 443)",
        type=int,
        default=443
    )
    parser.add_argument(
        "--warning-days", "-w",
        help="Days before expiration to warn (default: 30)",
        type=int,
        default=30
    )
    
    args = parser.parse_args()
    
    if not args.file and not args.domain:
        parser.print_help()
        sys.exit(1)
    
    checker = SSLCertificateChecker(warning_days=args.warning_days)
    
    if args.file:
        cert_info = checker.check_file(args.file)
        checker.print_info(cert_info)
    
    if args.domain:
        cert_info = checker.check_domain(args.domain, args.port)
        checker.print_info(cert_info)


if __name__ == "__main__":
    main()
