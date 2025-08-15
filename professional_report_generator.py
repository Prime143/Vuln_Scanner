#!/usr/bin/env python3
import json
from datetime import datetime
from reportlab.lib.pagesizes import letter, A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.colors import HexColor
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from reportlab.lib import colors
from detailed_vulnerability_db import DetailedVulnerabilityDatabase

class ProfessionalReportGenerator:
    def __init__(self):
        self.vuln_db = DetailedVulnerabilityDatabase()
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def generate_text_report(self, scan_results, executive_summary, filename=None):
        """Generate detailed text report"""
        if not filename:
            filename = f"reports/security_assessment_report_{self.timestamp}.txt"
        
        with open(filename, 'w') as f:
            # Header
            f.write("="*80 + "\n")
            f.write("           NETWORK SECURITY ASSESSMENT REPORT\n")
            f.write("="*80 + "\n")
            f.write(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Assessment Type: Automated Network Security Scan\n")
            f.write(f"Scan Duration: Network Discovery and Service Analysis\n\n")
            
            # Executive Summary
            f.write("EXECUTIVE SUMMARY\n")
            f.write("-" * 40 + "\n")
            f.write(f"Overall Network Risk Level: {executive_summary['overall_network_risk']}\n")
            f.write(f"Total Hosts Scanned: {executive_summary['total_hosts_scanned']}\n")
            f.write(f"Total Vulnerabilities Found: {executive_summary['total_vulnerabilities']}\n")
            f.write(f"Critical Risk Hosts: {executive_summary['critical_risk_hosts']}\n")
            f.write(f"High Risk Hosts: {executive_summary['high_risk_hosts']}\n\n")
            
            # Risk Assessment
            f.write("RISK ASSESSMENT SUMMARY\n")
            f.write("-" * 40 + "\n")
            total_critical = sum([r['vulnerability_assessment']['critical_count'] for r in scan_results])
            total_high = sum([r['vulnerability_assessment']['high_count'] for r in scan_results])
            total_medium = sum([r['vulnerability_assessment']['medium_count'] for r in scan_results])
            total_low = sum([r['vulnerability_assessment']['low_count'] for r in scan_results])
            
            f.write(f"Critical Vulnerabilities: {total_critical}\n")
            f.write(f"High Vulnerabilities: {total_high}\n")
            f.write(f"Medium Vulnerabilities: {total_medium}\n")
            f.write(f"Low Vulnerabilities: {total_low}\n\n")
            
            # Detailed Host Analysis
            f.write("DETAILED HOST ANALYSIS\n")
            f.write("=" * 40 + "\n\n")
            
            for i, result in enumerate(scan_results, 1):
                f.write(f"HOST {i}: {result['ip']}\n")
                f.write("-" * 30 + "\n")
                f.write(f"Risk Level: {result['risk_level']}\n")
                f.write(f"Scan Time: {result['scan_time']}\n")
                f.write(f"Services Discovered: {len(result['services'])}\n\n")
                
                # Services
                f.write("DISCOVERED SERVICES:\n")
                for service in result['services']:
                    f.write(f"  • Port {service['port']}: {service['service']} ({service['state']})\n")
                    if service.get('version'):
                        f.write(f"    Version: {service['version']}\n")
                f.write("\n")
                
                # Vulnerabilities
                if result['vulnerability_assessment']['total_vulnerabilities'] > 0:
                    f.write("VULNERABILITY DETAILS:\n")
                    f.write("~" * 25 + "\n")
                    
                    for vuln in result['vulnerability_assessment']['vulnerabilities']:
                        severity = vuln['severity'].upper()
                        f.write(f"\n[{severity}] {vuln['vulnerability_name']}\n")
                        f.write(f"Service: {vuln['service']} (Port {vuln['port']})\n")
                        f.write(f"Risk Score: {vuln['risk_score']}/10\n")
                        
                        # Get detailed information from database
                        service_vulns = self.vuln_db.get_vulnerabilities_for_service(vuln['service'])
                        detailed_vuln = None
                        for sv in service_vulns:
                            if sv['name'] in vuln['vulnerability_name'] or vuln['vulnerability_name'] in sv['name']:
                                detailed_vuln = sv
                                break
                        
                        if detailed_vuln:
                            f.write(f"CVSS Score: {detailed_vuln['cvss_score']}\n")
                            f.write(f"\nDescription:\n{detailed_vuln['description']}\n")
                            f.write(f"\nTechnical Details:\n{detailed_vuln['technical_details']}\n")
                            f.write(f"\nPotential Impact:\n{detailed_vuln['impact']}\n")
                            f.write(f"\nRemediation Steps:\n")
                            for step in detailed_vuln['remediation']:
                                f.write(f"  {step}\n")
                            f.write(f"\nPriority: {detailed_vuln['priority']}\n")
                            f.write(f"References: {', '.join(detailed_vuln['references'])}\n")
                        
                        f.write("\n" + "-" * 50 + "\n")
                else:
                    f.write("No vulnerabilities detected for this host.\n")
                
                f.write("\n" + "=" * 60 + "\n\n")
            
            # Recommendations
            f.write("PRIORITY REMEDIATION RECOMMENDATIONS\n")
            f.write("=" * 45 + "\n")
            for i, rec in enumerate(executive_summary['top_recommendations'], 1):
                f.write(f"{i}. {rec}\n")
            
            # Severity Guide
            f.write(f"\n\nSEVERITY LEVEL GUIDE\n")
            f.write("=" * 25 + "\n")
            for severity in ['critical', 'high', 'medium', 'low']:
                sev_info = self.vuln_db.get_severity_explanation(severity)
                f.write(f"\n{severity.upper()}:\n")
                f.write(f"  Description: {sev_info['description']}\n")
                f.write(f"  Impact: {sev_info['impact']}\n")
                f.write(f"  Timeline: {sev_info['timeline']}\n")
            
            f.write(f"\n\n" + "="*80 + "\n")
            f.write("Report End - Generated by Network Security Assessment Dashboard\n")
            f.write("="*80 + "\n")
        
        print(f"[+] Detailed text report saved to: {filename}")
        return filename
    
    def generate_pdf_report(self, scan_results, executive_summary, filename=None):
        """Generate professional PDF report"""
        if not filename:
            filename = f"reports/security_assessment_report_{self.timestamp}.pdf"
        
        doc = SimpleDocTemplate(filename, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=18,
            spaceAfter=30,
            alignment=1,  # Center alignment
            textColor=colors.darkblue
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=14,
            spaceAfter=12,
            textColor=colors.darkred
        )
        
        # Title
        story.append(Paragraph("NETWORK SECURITY ASSESSMENT REPORT", title_style))
        story.append(Spacer(1, 12))
        story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("EXECUTIVE SUMMARY", heading_style))
        summary_data = [
            ["Metric", "Value"],
            ["Overall Network Risk", executive_summary['overall_network_risk']],
            ["Total Hosts Scanned", str(executive_summary['total_hosts_scanned'])],
            ["Total Vulnerabilities", str(executive_summary['total_vulnerabilities'])],
            ["Critical Risk Hosts", str(executive_summary['critical_risk_hosts'])],
            ["High Risk Hosts", str(executive_summary['high_risk_hosts'])]
        ]
        
        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 14),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(summary_table)
        story.append(Spacer(1, 20))
        
        # Detailed findings for each host
        for i, result in enumerate(scan_results, 1):
            story.append(Paragraph(f"HOST {i}: {result['ip']}", heading_style))
            story.append(Paragraph(f"Risk Level: <b>{result['risk_level']}</b>", styles['Normal']))
            story.append(Paragraph(f"Services Found: {len(result['services'])}", styles['Normal']))
            story.append(Spacer(1, 12))
            
            # Vulnerabilities
            if result['vulnerability_assessment']['total_vulnerabilities'] > 0:
                story.append(Paragraph("Vulnerabilities Found:", styles['Heading3']))
                
                for vuln in result['vulnerability_assessment']['vulnerabilities']:
                    severity_color = {
                        'critical': colors.red,
                        'high': colors.orange,
                        'medium': colors.yellow,
                        'low': colors.green
                    }.get(vuln['severity'], colors.black)
                    
                    vuln_style = ParagraphStyle(
                        'VulnStyle',
                        parent=styles['Normal'],
                        leftIndent=20,
                        textColor=severity_color
                    )
                    
                    story.append(Paragraph(f"<b>[{vuln['severity'].upper()}]</b> {vuln['vulnerability_name']}", vuln_style))
                    story.append(Paragraph(f"Service: {vuln['service']} (Port {vuln['port']})", styles['Normal']))
                    story.append(Paragraph(f"Risk Score: {vuln['risk_score']}/10", styles['Normal']))
                    story.append(Spacer(1, 8))
            else:
                story.append(Paragraph("No vulnerabilities detected.", styles['Normal']))
            
            story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("RECOMMENDATIONS", heading_style))
        for i, rec in enumerate(executive_summary['top_recommendations'], 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
            story.append(Spacer(1, 6))
        
        doc.build(story)
        print(f"[+] Professional PDF report saved to: {filename}")
        return filename
