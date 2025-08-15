#!/usr/bin/env python3
import subprocess
import json
import datetime
import os
import time

class EnhancedNetworkScanner:
    def __init__(self):
        self.scan_results = {}
        self.timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def discover_network(self, target_network="192.168.1.0/24"):
        """Discover live hosts on the network"""
        print(f"[+] Discovering hosts on {target_network}...")
        
        cmd = f"nmap -sn {target_network}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        live_hosts = []
        for line in result.stdout.split('\n'):
            if "Nmap scan report for" in line:
                ip = line.split()[-1].strip('()')
                live_hosts.append(ip)
        
        print(f"[+] Found {len(live_hosts)} live hosts")
        return live_hosts
    
    def security_assessment_scan(self, target_ip):
        """Perform comprehensive security assessment"""
        print(f"[+] Performing security assessment on {target_ip}...")
        
        cmd = f"nmap -sV -A {target_ip}"
        result = subprocess.run(cmd.split(), capture_output=True, text=True)
        
        services = self.parse_services(result.stdout)
        
        # Simple vulnerability analysis
        vulnerabilities = self.analyze_vulnerabilities(services, target_ip)
        vuln_report = self.generate_vulnerability_report(vulnerabilities)
        
        return {
            'ip': target_ip,
            'scan_time': datetime.datetime.now().isoformat(),
            'services': services,
            'nmap_output': result.stdout,
            'vulnerability_assessment': vuln_report,
            'risk_level': self.calculate_host_risk(vuln_report)
        }
    
    def parse_services(self, nmap_output):
        """Extract services from Nmap output"""
        services = []
        lines = nmap_output.split('\n')
        
        for line in lines:
            if '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port = parts[0]
                    state = parts[1]
                    service = parts[2] if len(parts) > 2 else "unknown"
                    version = ' '.join(parts[3:]) if len(parts) > 3 else ""
                    
                    services.append({
                        'port': port,
                        'state': state,
                        'service': service,
                        'version': version
                    })
        
        return services
    
    def analyze_vulnerabilities(self, services, target_ip):
        """Simple vulnerability analysis"""
        vulnerabilities = []
        
        vuln_db = {
            'ssh': [{'name': 'SSH Password Authentication', 'severity': 'medium', 'risk_score': 5}],
            'http': [{'name': 'HTTP Unencrypted Traffic', 'severity': 'high', 'risk_score': 8}],
            'ftp': [{'name': 'FTP Cleartext Authentication', 'severity': 'high', 'risk_score': 8}],
            'telnet': [{'name': 'Telnet Cleartext Protocol', 'severity': 'critical', 'risk_score': 10}]
        }
        
        for service in services:
            service_name = service['service'].lower()
            if service_name in vuln_db:
                for vuln in vuln_db[service_name]:
                    vulnerabilities.append({
                        'target_ip': target_ip,
                        'service': service_name,
                        'port': service['port'],
                        'vulnerability_name': vuln['name'],
                        'severity': vuln['severity'],
                        'risk_score': vuln['risk_score']
                    })
        
        return vulnerabilities
    
    def generate_vulnerability_report(self, vulnerabilities):
        """Generate vulnerability report"""
        if not vulnerabilities:
            return {
                "scan_timestamp": datetime.datetime.now().isoformat(),
                "total_vulnerabilities": 0,
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "low_count": 0,
                "vulnerabilities": []
            }
        
        severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        for vuln in vulnerabilities:
            severity_counts[vuln['severity']] += 1
        
        return {
            "scan_timestamp": datetime.datetime.now().isoformat(),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_count": severity_counts['critical'],
            "high_count": severity_counts['high'],
            "medium_count": severity_counts['medium'],
            "low_count": severity_counts['low'],
            "vulnerabilities": vulnerabilities
        }
    
    def calculate_host_risk(self, vuln_report):
        """Calculate overall host risk level"""
        critical_count = vuln_report.get('critical_count', 0)
        high_count = vuln_report.get('high_count', 0)
        medium_count = vuln_report.get('medium_count', 0)
        low_count = vuln_report.get('low_count', 0)
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0 or medium_count > 3:
            return "MEDIUM"
        elif medium_count > 0 or low_count > 5:
            return "LOW"
        else:
            return "MINIMAL"
    
    def generate_executive_summary(self, all_results):
        """Generate executive summary"""
        total_hosts = len(all_results)
        critical_hosts = len([r for r in all_results if r['risk_level'] == 'CRITICAL'])
        high_risk_hosts = len([r for r in all_results if r['risk_level'] == 'HIGH'])
        
        total_vulns = sum([r['vulnerability_assessment'].get('total_vulnerabilities', 0) for r in all_results])
        
        summary = {
            'assessment_date': datetime.datetime.now().isoformat(),
            'total_hosts_scanned': total_hosts,
            'critical_risk_hosts': critical_hosts,
            'high_risk_hosts': high_risk_hosts,
            'total_vulnerabilities': total_vulns,
            'overall_network_risk': 'CRITICAL' if critical_hosts > 0 else 'HIGH' if high_risk_hosts > 0 else 'MEDIUM',
            'top_recommendations': [
                "Implement strong authentication mechanisms",
                "Enable encryption for all network services",
                "Regular security patching and updates",
                "Configure firewall rules properly",
                "Conduct regular security assessments"
            ]
        }
        
        return summary

class InteractiveDashboard:
    def __init__(self):
        self.scanner = EnhancedNetworkScanner()
        self.scan_history = []
        self.running = True
        self.current_network = "192.168.1.0/24"
    
    def clear_screen(self):
        os.system('clear' if os.name == 'posix' else 'cls')
    
    def print_banner(self):
        banner = """
╔════════════════════════════════════════════════════════════════════════════╗
║                    🛡️  NETWORK SECURITY DASHBOARD 🛡️                     ║
║                        🔥 LIVE THREAT ANALYSIS SYSTEM 🔥                   ║
╚════════════════════════════════════════════════════════════════════════════╝
"""
        print(banner)
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        print(f"🕒 System Time: {current_time}")
        print(f"🌐 Target Network: {self.current_network}")
        print(f"📊 Completed Scans: {len(self.scan_history)}")
        print("═" * 80)
    
    def show_main_menu(self):
        menu = """
🎯 SECURITY COMMAND CENTER:

1️⃣  🚀 FULL NETWORK SECURITY SCAN    - Complete vulnerability assessment
2️⃣  🔍 QUICK NETWORK DISCOVERY       - Rapid host enumeration  
3️⃣  📊 VIEW SCAN HISTORY            - Review previous operations
4️⃣  📝 GENERATE SECURITY REPORTS     - Professional documentation
5️⃣  ⚙️  CONFIGURE NETWORK RANGE      - Change target scope
6️⃣  🛡️  SECURITY RECOMMENDATIONS     - Best practice guidance
7️⃣  🔧 SYSTEM STATUS                - Dashboard diagnostics
0️⃣  🚪 EXIT DASHBOARD               - Shutdown system

💬 NATURAL LANGUAGE: Try asking "what can you do?" or "help"
🗣️  EXAMPLES: "scan network", "find hosts", "show reports", "exit"
═══════════════════════════════════════════════════════════════════════════════
"""
        print(menu)

    def handle_natural_language(self, user_input: str):
        """
        Understand free-form requests and execute the right action, then present
        a concise, helpful solution-oriented response.
        """
        text = user_input.strip().lower()

        # Fast exits
        if not text:
            print("\n🤖 I didn't catch that. Try 'scan the network' or 'find vulnerabilities'.")
            input("\n⏎ Press ENTER to continue...")
            return

        # 0) Help / capabilities
        if any(k in text for k in ["help", "what can you do", "capabilities", "menu", "options"]):
            self.show_help()
            return

        # 1) Vulnerability intent: scan + summarize + remediation
        if any(k in text for k in [
            "find vulnerabilities", "vulnerabilities", "vulnerability", "security issues", "weaknesses",
            "check my network", "scan my network", "scan the network", "security assessment", "pentest", "audit"
        ]):
            print("\n🛡️ Understood: You want me to identify vulnerabilities and how to fix them.")
            # If there is no scan data, run a scan first (quick prompt to limit scope)
            if not self.scan_history:
                print("🔎 No prior scans found. Running a focused network assessment...")
                self.full_network_scan()  # Will populate history and summary
            else:
                print("📊 Using the latest scan results in memory...")

            # Use latest results
            if not self.scan_history:
                print("⚠️ No results available. Try 'scan' to collect data first.")
                input("\n⏎ Press ENTER to continue...")
                return

            latest = self.scan_history[-1]
            results = latest["results"]
            summary = latest["summary"]

            # Present a concise vulnerability summary + fixes
            self._present_vuln_findings_with_fixes(results, summary)
            input("\n⏎ Press ENTER to continue...")
            return

        # 2) Discovery intent
        if any(k in text for k in ["discover", "find hosts", "list hosts", "who is online", "recon", "discovery"]):
            self.quick_network_discovery()
            return

        # 3) Report intent
        if any(k in text for k in ["report", "generate report", "export", "documentation", "save findings"]):
            self.smart_report_generation()
            return

        # 4) Status / history intent
        if any(k in text for k in ["history", "previous scans", "past scans", "logs", "what did we find"]):
            self.view_scan_history()
            return

        # 5) Config / network target
        if any(k in text for k in ["change network", "set network", "configure", "settings", "target range"]):
            self.configure_network_range()
            return

        # 6) Recommendations request (general)
        if any(k in text for k in ["recommendations", "best practices", "how to be secure", "improve security"]):
            self.security_recommendations()
            return

        # 7) Exit intent
        if any(k in text for k in ["exit", "quit", "bye", "shutdown", "close", "stop"]):
            # Mirror normal exit path
            print(f"\n🛑 SHUTTING DOWN...")
            print(f"📊 Scans completed: {len(self.scan_history)}")
            print("✅ Goodbye!")
            self.running = False
            return

        # Fallback
        print(f"\n🤔 I can’t map that to an action yet.")
        print("Try: ‘find vulnerabilities in my network’, ‘scan my network’, ‘generate report’, or ‘help’.")
        input("\n⏎ Press ENTER to continue...")

    
    def parse_command(self, user_input):     # 4 spaces
        cmd = user_input.lower().strip()     # 8 spaces
        
        if cmd in ['1', '2', '3', '4', '5', '6', '7', '0']:  # 8 spaces
            return cmd                       # 12 spaces
    def parse_command(self, user_input):
        cmd = user_input.lower().strip()
        
        # Direct number commands
        if cmd in ['1', '2', '3', '4', '5', '6', '7', '0']:
            return cmd
        
        # Help and general questions
        if any(word in cmd for word in ['help', 'what can you do', 'options', 'commands', 'menu']):
            return 'help'
        
        # Natural language parsing
        if any(word in cmd for word in ['scan', 'network', 'full', 'security', 'assess', 'check']):
            return '1'
        elif any(word in cmd for word in ['discover', 'quick', 'find', 'hosts', 'recon', 'ping']):
            return '2'  
        elif any(word in cmd for word in ['history', 'previous', 'past', 'log', 'show scans']):
            return '3'
        elif any(word in cmd for word in ['report', 'generate', 'document', 'export', 'save']):
            return '4'
        elif any(word in cmd for word in ['config', 'settings', 'network', 'change', 'setup']):
            return '5'
        elif any(word in cmd for word in ['recommend', 'best', 'practice', 'guide', 'tips']):
            return '6'
        elif any(word in cmd for word in ['status', 'system', 'diagnostic', 'info']):
            return '7'
        elif any(word in cmd for word in ['exit', 'quit', 'bye', 'close', 'shutdown', 'stop']):
            return '0'
        
        return 'invalid'

    
    def full_network_scan(self):
        print(f"\n🚀 INITIATING FULL NETWORK SECURITY SCAN")
        print("═" * 60)
        print(f"🎯 Target Network: {self.current_network}")
        
        try:
            hosts = self.scanner.discover_network(self.current_network)
            
            if not hosts:
                print("⚠️  No hosts detected. Scanning localhost...")
                hosts = ["127.0.0.1"]
            
            print(f"✅ DISCOVERY COMPLETE: {len(hosts)} live targets")
            
            if len(hosts) > 5:
                while True:
                    try:
                        max_hosts = input(f"🎛️  Scan how many hosts? (1-{len(hosts)}, Enter=3): ").strip()
                        if not max_hosts:
                            max_hosts = 3
                        else:
                            max_hosts = int(max_hosts)
                        
                        if 1 <= max_hosts <= len(hosts):
                            break
                        print(f"❌ Please enter 1-{len(hosts)}")
                    except ValueError:
                        print("❌ Invalid input")
            else:
                max_hosts = len(hosts)
            
            print(f"\n⚡ SCANNING {max_hosts} TARGETS...")
            all_results = []
            
            for i, host in enumerate(hosts[:max_hosts], 1):
                print(f"\n🎯 [{i}/{max_hosts}] SCANNING: {host}")
                
                result = self.scanner.security_assessment_scan(host)
                all_results.append(result)
                
                risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'MINIMAL': '⚪'}
                risk_symbol = risk_icons.get(result['risk_level'], '⚪')
                vuln_count = result['vulnerability_assessment']['total_vulnerabilities']
                
                print(f"   ✅ Risk: {risk_symbol} {result['risk_level']} | Vulns: {vuln_count}")
            
            summary = self.scanner.generate_executive_summary(all_results)
            
            scan_record = {
                'timestamp': datetime.datetime.now().isoformat(),
                'scan_type': 'Full Network Security Assessment',
                'hosts_scanned': len(all_results),
                'results': all_results,
                'summary': summary
            }
            self.scan_history.append(scan_record)
            
            self.display_scan_results(summary, all_results)
            
            if input("\n📝 Generate report? (y/n): ").lower().startswith('y'):
                self.generate_simple_report(all_results, summary)
        
        except Exception as e:
            print(f"\n❌ SCAN ERROR: {e}")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def quick_network_discovery(self):
        print(f"\n🔍 RAPID NETWORK DISCOVERY")
        print("═" * 35)
        
        try:
            hosts = self.scanner.discover_network(self.current_network)
            
            if hosts:
                print(f"\n✅ FOUND {len(hosts)} ACTIVE HOSTS:")
                for i, host in enumerate(hosts, 1):
                    print(f"  {i:2d}. 🖥️  {host}")
            else:
                print(f"\n⚠️  NO HOSTS FOUND")
        
        except Exception as e:
            print(f"\n❌ ERROR: {e}")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def view_scan_history(self):
        if not self.scan_history:
            print(f"\n📊 NO SCAN HISTORY AVAILABLE")
            input(f"\n⏎ Press ENTER to continue...")
            return
        
        print(f"\n📊 SCAN HISTORY ({len(self.scan_history)} records)")
        print("═" * 40)
        
        for i, record in enumerate(self.scan_history[-5:], 1):
            timestamp = datetime.datetime.fromisoformat(record['timestamp']).strftime('%m/%d %H:%M')
            hosts_count = record['hosts_scanned']
            total_vulns = record['summary']['total_vulnerabilities']
            risk_level = record['summary']['overall_network_risk']
            
            risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'MINIMAL': '⚪'}
            risk_icon = risk_icons.get(risk_level, '⚪')
            
            print(f"  {i}. [{timestamp}] Network Scan")
            print(f"     🎯 Hosts: {hosts_count} | {risk_icon} {risk_level} | ⚠️  {total_vulns} vulns")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def smart_report_generation(self):
        if not self.scan_history:
            print("🔍 NO SCAN DATA AVAILABLE")
            print("Run a network scan first!")
            input("\n⏎ Press ENTER to continue...")
            return
        
        print(f"\n📝 GENERATING REPORT FROM LATEST SCAN...")
        
        latest_scan = self.scan_history[-1]
        self.generate_simple_report(latest_scan['results'], latest_scan['summary'])
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def generate_simple_report(self, results, summary):
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        os.makedirs("reports", exist_ok=True)
        
        filename = f"reports/security_report_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("="*60 + "\n")
            f.write("     NETWORK SECURITY ASSESSMENT REPORT\n")
            f.write("="*60 + "\n")
            f.write(f"Report Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
            
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-"*20 + "\n")
            f.write(f"Overall Risk Level: {summary['overall_network_risk']}\n")
            f.write(f"Total Hosts Scanned: {summary['total_hosts_scanned']}\n")
            f.write(f"Total Vulnerabilities: {summary['total_vulnerabilities']}\n")
            f.write(f"Critical Risk Hosts: {summary['critical_risk_hosts']}\n")
            f.write(f"High Risk Hosts: {summary['high_risk_hosts']}\n\n")
            
            f.write("DETAILED FINDINGS\n")
            f.write("-"*20 + "\n")
            for i, result in enumerate(results, 1):
                f.write(f"\nHost {i}: {result['ip']}\n")
                f.write(f"Risk Level: {result['risk_level']}\n")
                f.write(f"Services: {len(result['services'])}\n")
                f.write(f"Vulnerabilities: {result['vulnerability_assessment']['total_vulnerabilities']}\n")
            
            f.write(f"\nRECOMMENDATIONS\n")
            f.write("-"*20 + "\n")
            for i, rec in enumerate(summary['top_recommendations'], 1):
                f.write(f"{i}. {rec}\n")
        
        print(f"✅ REPORT GENERATED: {filename}")
    
    def configure_network_range(self):
        print(f"\n⚙️  NETWORK CONFIGURATION")
        print(f"Current: {self.current_network}")
        
        new_network = input("Enter new network range: ").strip()
        if new_network:
            self.current_network = new_network
            print(f"✅ Updated to: {self.current_network}")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def security_recommendations(self):
        print(f"\n🛡️  SECURITY RECOMMENDATIONS")
        print("═" * 35)
        
        recommendations = [
            "🔐 Strong passwords and multi-factor authentication",
            "🔄 Regular security patching and updates",
            "🔥 Firewall configuration with least privilege",
            "📊 Regular vulnerability assessments",
            "💾 Secure backup strategies"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            print(f"  {i}. {rec}")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def system_status(self):
        print(f"\n🔧 SYSTEM STATUS")
        print("═" * 20)
        print(f"🖥️  Dashboard: 🟢 OPERATIONAL")
        print(f"🌐 Network: {self.current_network}")
        print(f"📊 Scans: {len(self.scan_history)}")
        
        input(f"\n⏎ Press ENTER to continue...")
    
    def display_scan_results(self, summary, results):
        print(f"\n🎊 SCAN COMPLETED!")
        print("═" * 25)
        
        risk_icons = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'LOW': '🟢', 'MINIMAL': '⚪'}
        risk_symbol = risk_icons.get(summary['overall_network_risk'], '⚪')
        
        print(f"🎚️  Risk: {risk_symbol} {summary['overall_network_risk']}")
        print(f"🖥️  Hosts: {summary['total_hosts_scanned']}")  
        print(f"⚠️  Vulnerabilities: {summary['total_vulnerabilities']}")
        print(f"🔴 Critical: {summary['critical_risk_hosts']}")
        print(f"🟠 High: {summary['high_risk_hosts']}")
    
    def run_dashboard(self):
        print("🚀 STARTING SECURITY DASHBOARD...")
        time.sleep(0.5)
        
        while self.running:
            try:
                self.clear_screen()
                self.print_banner()
                self.show_main_menu()
                
                user_input = input("🎯 COMMAND > ").strip()
                choice = self.parse_command(user_input)
                
                if choice == '1':
                    self.full_network_scan()
                elif choice == '2':
                    self.quick_network_discovery()
                elif choice == '3':
                    self.view_scan_history()
                elif choice == '4':
                    self.smart_report_generation()
                elif choice == '5':
                    self.configure_network_range()
                elif choice == '6':
                    self.security_recommendations()
                elif choice == '7':
                    self.system_status()
                elif choice == '0':
                    print(f"\n🛑 SHUTTING DOWN...")
                    print(f"📊 Scans completed: {len(self.scan_history)}")
                    print("✅ Goodbye!")
                    self.running = False
                else:
                    print(f"\n❌ UNKNOWN COMMAND: '{user_input}'")
                    print("🎯 Try: 'scan', 'discover', 'report', or numbers 0-7")
                    time.sleep(2)
            
            except KeyboardInterrupt:
                print(f"\n⚠️  Use 'exit' or '0' to shutdown properly")
                time.sleep(2)
            except Exception as e:
                print(f"\n💥 ERROR: {e}")
                input("⏎ Press ENTER...")

if __name__ == "__main__":
    print("🚀 Launching Interactive Security Dashboard...")
    time.sleep(0.5)
    
    dashboard = InteractiveDashboard()
    dashboard.run_dashboard()


def show_help(self):
    print(f"\n🤖 SECURITY DASHBOARD HELP SYSTEM")
    print("═" * 45)
    print("I can understand both numbers and natural language!")
    print()
    print("📋 AVAILABLE COMMANDS:")
    print("• 'scan' or '1' → Full network security scan")
    print("• 'discover' or '2' → Quick network discovery")
    print("• 'history' or '3' → View previous scans")
    print("• 'report' or '4' → Generate security reports")
    print("• 'config' or '5' → Change network settings")
    print("• 'recommend' or '6' → Security best practices")
    print("• 'status' or '7' → System information")
    print("• 'exit' or '0' → Quit dashboard")
    print()
    print("💬 NATURAL LANGUAGE EXAMPLES:")
    print("• 'What can you do?' → Shows this help")
    print("• 'Scan my network' → Starts security scan")
    print("• 'Find hosts' → Network discovery")
    print("• 'Show me reports' → Generate reports")
    print("• 'Change settings' → Configuration menu")
    
    input(f"\n⏎ Press ENTER to return to main menu...")
