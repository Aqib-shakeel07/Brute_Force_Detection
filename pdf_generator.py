# pdf_generator.py
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

# Try to import reportlab
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, landscape
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib.enums import TA_CENTER, TA_LEFT
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
    logger.info("ReportLab loaded successfully")
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("ReportLab not installed. PDF export will be disabled.")

class PDFGenerator:
    """Generate PDF reports for IP analysis"""
    
    def generate_report(self, data, summary, filename='report.pdf', is_enriched=False):
        """Generate PDF report"""
        if not REPORTLAB_AVAILABLE:
            logger.error("ReportLab not available. Please install: pip install reportlab")
            return False
        
        try:
            doc = SimpleDocTemplate(
                filename,
                pagesize=letter,
                rightMargin=72,
                leftMargin=72,
                topMargin=72,
                bottomMargin=72
            )
            
            styles = getSampleStyleSheet()
            story = []
            
            # ============================================================
            # TITLE SECTION
            # ============================================================
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=28,
                textColor=colors.darkblue,
                spaceAfter=10,
                alignment=TA_CENTER
            )
            story.append(Paragraph("Threat Intelligence Report", title_style))
            
            # Subtitle
            subtitle_style = ParagraphStyle(
                'Subtitle',
                parent=styles['Normal'],
                fontSize=14,
                textColor=colors.grey,
                spaceAfter=20,
                alignment=TA_CENTER
            )
            report_type = "Top 10 Most Malicious IPs" if is_enriched else "Full Analysis Report"
            story.append(Paragraph(f"{report_type}", subtitle_style))
            
            # Date
            date_style = ParagraphStyle(
                'Date',
                parent=styles['Normal'],
                fontSize=11,
                textColor=colors.grey,
                spaceAfter=25,
                alignment=TA_CENTER
            )
            story.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", date_style))
            
            # ============================================================
            # EXECUTIVE SUMMARY
            # ============================================================
            story.append(Paragraph("Executive Summary", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            summary_data = []
            
            if is_enriched:
                # Only show relevant stats for enriched report
                summary_data = [
                    ['Total Enriched IPs', str(summary.get('enriched_count', 0))],
                    ['Critical Threats', str(summary.get('critical_count', 0))],
                    ['High Threats', str(summary.get('high_count', 0))],
                    ['Medium Threats', str(summary.get('medium_count', 0))],
                    ['Low Threats', str(summary.get('low_count', 0))]
                ]
            else:
                # Show full summary
                summary_data = [
                    ['Total Suspicious IPs', str(summary.get('suspicious_ips', 0))],
                    ['Public IPs', str(summary.get('public_count', 0))],
                    ['Private IPs', str(summary.get('private_count', 0))],
                    ['Critical Threats', str(summary.get('critical_count', 0))],
                    ['High Threats', str(summary.get('high_count', 0))],
                    ['Medium Threats', str(summary.get('medium_count', 0))],
                    ['Low Threats', str(summary.get('low_count', 0))],
                    ['Enriched IPs', str(summary.get('enriched_count', 0))]
                ]
            
            summary_table = Table(summary_data, colWidths=[3*inch, 2*inch])
            summary_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.lightgrey),
                ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, -1), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(summary_table)
            story.append(Spacer(1, 20))
            
            # ============================================================
            # IP DETAILS TABLE
            # ============================================================
            story.append(Paragraph("IP Details", styles['Heading2']))
            story.append(Spacer(1, 10))
            
            # Get the appropriate data
            if is_enriched:
                ip_list = data.get('enriched_ips', [])
            else:
                ip_list = data.get('all_ips', [])[:50]  # Limit to 50 for full report
            
            if ip_list:
                # Build table headers
                if is_enriched:
                    table_headers = ['#', 'IP', 'Type', 'Country', 'Attempts', 'Risk', 'VT Score', 'Abuse Score', 'Combined']
                    col_widths = [0.4*inch, 1.3*inch, 0.8*inch, 0.8*inch, 0.7*inch, 0.8*inch, 0.7*inch, 0.8*inch, 0.8*inch]
                else:
                    table_headers = ['#', 'IP', 'Type', 'Country', 'Attempts', 'Risk', 'VT Score', 'Abuse Score']
                    col_widths = [0.3*inch, 1.3*inch, 0.7*inch, 0.8*inch, 0.6*inch, 0.7*inch, 0.6*inch, 0.6*inch]
                
                table_data = [table_headers]
                
                for idx, ip in enumerate(ip_list[:20], 1):  # Max 20 rows per page
                    if is_enriched:
                        row = [
                            str(idx),
                            ip.get('ip', 'Unknown'),
                            ip.get('ip_type', 'Unknown'),
                            ip.get('country', 'Unknown')[:15],
                            str(ip.get('attempt_count', 0)),
                            ip.get('risk_level', 'Unknown'),
                            f"{ip.get('virustotal_score', 0)}%",
                            f"{ip.get('abuseipdb_score', 0)}%",
                            f"{ip.get('confidence', 0)}%"
                        ]
                    else:
                        row = [
                            str(idx),
                            ip.get('ip', 'Unknown'),
                            ip.get('ip_type', 'Unknown'),
                            ip.get('country', 'Unknown')[:15],
                            str(ip.get('attempt_count', 0)),
                            ip.get('risk_level', 'Unknown'),
                            f"{ip.get('virustotal_score', 0)}%",
                            f"{ip.get('abuseipdb_score', 0)}%"
                        ]
                    table_data.append(row)
                
                # Create the table
                ip_table = Table(table_data, colWidths=col_widths)
                
                # Style the table
                style_list = [
                    ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
                    ('TOPPADDING', (0, 0), (-1, -1), 6),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ]
                
                # Color rows alternately
                for i in range(1, len(table_data)):
                    if i % 2 == 0:
                        style_list.append(('BACKGROUND', (0, i), (-1, i), colors.lightgrey))
                    else:
                        style_list.append(('BACKGROUND', (0, i), (-1, i), colors.whitesmoke))
                
                ip_table.setStyle(TableStyle(style_list))
                story.append(ip_table)
                
                # Add note if there are more IPs
                if len(ip_list) > 20:
                    note_style = ParagraphStyle(
                        'Note',
                        parent=styles['Normal'],
                        fontSize=9,
                        textColor=colors.grey,
                        spaceAfter=10,
                        alignment=TA_LEFT
                    )
                    story.append(Paragraph(f"* Showing first 20 of {len(ip_list)} IPs", note_style))
            
            # ============================================================
            # FOOTER
            # ============================================================
            footer_style = ParagraphStyle(
                'Footer',
                parent=styles['Normal'],
                fontSize=8,
                textColor=colors.grey,
                alignment=TA_CENTER
            )
            story.append(Spacer(1, 20))
            story.append(Paragraph("This report was generated automatically by the Threat Intelligence Dashboard.", footer_style))
            story.append(Paragraph(f"Report ID: {datetime.now().strftime('%Y%m%d%H%M%S')} | Version: 2.4.1", footer_style))
            
            # ============================================================
            # BUILD PDF
            # ============================================================
            doc.build(story)
            logger.info(f"PDF report generated: {filename}")
            return True
            
        except Exception as e:
            logger.error(f"PDF generation error: {e}")
            import traceback
            traceback.print_exc()
            return False

# Singleton instance
_pdf_generator = None

def get_pdf_generator():
    global _pdf_generator
    if _pdf_generator is None:
        _pdf_generator = PDFGenerator()
    return _pdf_generator