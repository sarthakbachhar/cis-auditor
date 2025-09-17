#!/usr/bin/env python3
"""
Professional PDF Report Generator for CIS Auditor
Enhanced version with proper text wrapping and professional styling
Fixed: All percentages now show exactly 2 decimal places
"""

from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, A4
from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle, Paragraph, 
                                Spacer, PageBreak, KeepTogether, Frame, PageTemplate)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.pdfgen import canvas
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
from reportlab.graphics.shapes import Drawing, Rect, Line
from reportlab.graphics.charts.piecharts import Pie
from reportlab.graphics import renderPDF
import os
import datetime
import logging
import textwrap

logger = logging.getLogger(__name__)

class ProfessionalPDFReportGenerator:
    def __init__(self):
        self.styles = getSampleStyleSheet()
        self.setup_professional_styles()
        
        # Professional color scheme
        self.colors = {
            'primary': colors.HexColor('#1a365d'),
            'secondary': colors.HexColor('#2b77ad'),
            'success': colors.HexColor('#38a169'),
            'danger': colors.HexColor('#e53e3e'),
            'warning': colors.HexColor('#d69e2e'),
            'gray_50': colors.HexColor('#f9fafb'),
            'gray_100': colors.HexColor('#f3f4f6'),
            'gray_200': colors.HexColor('#e5e7eb'),
            'gray_500': colors.HexColor('#6b7280'),
            'gray_600': colors.HexColor('#4b5563'),
            'gray_700': colors.HexColor('#374151'),
            'gray_800': colors.HexColor('#1f2937'),
        }
    
    def setup_professional_styles(self):
        """Setup professional styles for the PDF with proper text wrapping"""
        
        # Main title style
        self.styles.add(ParagraphStyle(
            name='ReportTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            spaceAfter=8,
            alignment=TA_CENTER,
            textColor=colors.white,
            fontName='Helvetica-Bold',
            wordWrap='CJK'
        ))
        
        # Subtitle style
        self.styles.add(ParagraphStyle(
            name='ReportSubtitle',
            parent=self.styles['Normal'],
            fontSize=14,
            spaceAfter=20,
            alignment=TA_CENTER,
            textColor=colors.white,
            fontName='Helvetica',
            wordWrap='CJK'
        ))
        
        # Section title style
        self.styles.add(ParagraphStyle(
            name='SectionTitle',
            parent=self.styles['Heading2'],
            fontSize=16,
            spaceAfter=12,
            spaceBefore=20,
            textColor=self.colors['primary'],
            fontName='Helvetica-Bold',
            wordWrap='CJK'
        ))
        
        # Executive summary style with proper text wrapping
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['Normal'],
            fontSize=10,
            spaceAfter=8,
            textColor=self.colors['gray_700'],
            fontName='Helvetica',
            alignment=TA_JUSTIFY,
            wordWrap='CJK',
            leftIndent=0,
            rightIndent=0
        ))
        
        # Check description style with better wrapping
        self.styles.add(ParagraphStyle(
            name='CheckDescription',
            parent=self.styles['Normal'],
            fontSize=9,
            spaceAfter=4,
            textColor=self.colors['gray_800'],
            fontName='Helvetica',
            wordWrap='CJK',
            leftIndent=0,
            rightIndent=0
        ))
        
        # Remediation style with proper text handling
        self.styles.add(ParagraphStyle(
            name='RemediationText',
            parent=self.styles['Normal'],
            fontSize=8,
            spaceAfter=4,
            textColor=self.colors['gray_700'],
            fontName='Helvetica',
            wordWrap='CJK',
            leftIndent=0,
            rightIndent=0,
            alignment=TA_LEFT
        ))
        
        # Status style
        self.styles.add(ParagraphStyle(
            name='StatusText',
            parent=self.styles['Normal'],
            fontSize=9,
            fontName='Helvetica-Bold',
            alignment=TA_CENTER,
            wordWrap='CJK'
        ))
        
        # Footer style
        self.styles.add(ParagraphStyle(
            name='Footer',
            parent=self.styles['Normal'],
            fontSize=8,
            textColor=self.colors['gray_600'],
            alignment=TA_CENTER,
            fontName='Helvetica'
        ))

    def format_percentage(self, value):
        """Format percentage to exactly 2 decimal places"""
        return f"{value:.2f}"

    def wrap_text(self, text, max_length=80):
        """Wrap text to prevent overflow"""
        if not text:
            return ""
        
        # Use textwrap to handle long text
        wrapped_lines = textwrap.wrap(str(text), width=max_length, break_long_words=True, break_on_hyphens=True)
        return '<br/>'.join(wrapped_lines)

    def truncate_text(self, text, max_length=100):
        """Truncate text if too long"""
        if not text:
            return ""
        text = str(text)
        if len(text) <= max_length:
            return text
        return text[:max_length-3] + "..."

    def create_header_background(self, canvas, width, height):
        """Create a professional gradient header background"""
        gradient_height = 100
        steps = 30
        
        for i in range(steps):
            y_pos = height - gradient_height + (i * gradient_height / steps)
            color_intensity = 1.0 - (i / steps * 0.4)
            
            canvas.setFillColor(colors.Color(
                0.1 * color_intensity,
                0.21 * color_intensity,
                0.36 * color_intensity,
                alpha=0.9
            ))
            canvas.rect(0, y_pos, width, gradient_height/steps, fill=1, stroke=0)

    def create_compliance_chart(self, passed_checks, failed_checks):
        """Create a professional pie chart for compliance visualization"""
        drawing = Drawing(120, 80)
        
        pie = Pie()
        pie.x = 20
        pie.y = 15
        pie.width = 50
        pie.height = 50
        
        total = passed_checks + failed_checks
        if total > 0:
            pie.data = [passed_checks, failed_checks]
            pie.labels = ['Pass', 'Fail']
            pie.slices.fillColor = self.colors['success']
            pie.slices[1].fillColor = self.colors['danger']
        else:
            pie.data = [1]
            pie.labels = ['No Data']
            pie.slices.fillColor = self.colors['gray_200']
        
        pie.slices.strokeWidth = 1
        pie.slices.strokeColor = colors.white
        drawing.add(pie)
        
        return drawing

    def create_summary_table(self, target):
        """Create professional summary metrics table"""
        total_checks = len(target.results)
        passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
        failed_checks = total_checks - passed_checks
        compliance_pct = round((passed_checks / total_checks * 100), 2) if total_checks > 0 else 0.00
        failed_pct = round((failed_checks / total_checks * 100), 2) if total_checks > 0 else 0.00
        
        summary_data = [
            ['Metric', 'Count', 'Percentage'],
            ['Total Controls', str(total_checks), '100.00%'],
            ['Compliant Controls', str(passed_checks), f'{self.format_percentage(compliance_pct)}%'],
            ['Non-Compliant Controls', str(failed_checks), f'{self.format_percentage(failed_pct)}%'],
            ['Overall Compliance', f'{passed_checks}/{total_checks}', f'{self.format_percentage(compliance_pct)}%'],
        ]
        
        summary_table = Table(summary_data, colWidths=[2.5*inch, 1.2*inch, 1.3*inch])
        
        table_style = [
            # Header styling
            ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
            ('TOPPADDING', (0, 0), (-1, 0), 8),
            
            # Data rows
            ('BACKGROUND', (0, 1), (-1, -1), colors.white),
            ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
            ('FONTSIZE', (0, 1), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, self.colors['gray_200']),
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            
            # Alternating row colors
            ('ROWBACKGROUNDS', (0, 1), (-1, -2), [colors.white, self.colors['gray_50']]),
            
            # Highlight final compliance row
            ('BACKGROUND', (0, -1), (-1, -1), self.colors['secondary']),
            ('TEXTCOLOR', (0, -1), (-1, -1), colors.white),
            ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ]
        
        summary_table.setStyle(TableStyle(table_style))
        return summary_table

    def create_metadata_section(self, target):
        """Create professional metadata section with proper spacing"""
        duration_str = str(target.end_time - target.start_time).split('.')[0] if target.start_time and target.end_time else 'N/A'
        
        metadata_data = [
            [
                Paragraph('<b>Target System:</b><br/>' + self.truncate_text(target.ip, 30), self.styles['ExecutiveSummary']),
                Paragraph('<b>Operating System:</b><br/>' + target.os.upper(), self.styles['ExecutiveSummary'])
            ],
            [
                Paragraph('<b>Audit Level:</b><br/>' + target.level.upper(), self.styles['ExecutiveSummary']),
                Paragraph('<b>Duration:</b><br/>' + duration_str, self.styles['ExecutiveSummary'])
            ],
            [
                Paragraph('<b>Report Date:</b><br/>' + datetime.datetime.now().strftime('%Y-%m-%d'), self.styles['ExecutiveSummary']),
                Paragraph('<b>Report Time:</b><br/>' + datetime.datetime.now().strftime('%H:%M:%S'), self.styles['ExecutiveSummary'])
            ]
        ]
        
        metadata_table = Table(metadata_data, colWidths=[2.5*inch, 2.5*inch])
        metadata_table.setStyle(TableStyle([
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('TOPPADDING', (0, 0), (-1, -1), 4),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
            ('LEFTPADDING', (0, 0), (-1, -1), 0),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        
        return metadata_table

    def generate_pdf_report(self, target, output_path):
        """Generate professional PDF report with proper text handling"""
        try:
            # Create PDF document
            doc = SimpleDocTemplate(
                output_path,
                pagesize=A4,
                topMargin=1.2*inch,
                bottomMargin=0.8*inch,
                leftMargin=0.6*inch,
                rightMargin=0.6*inch
            )
            
            story = []
            
            # Header drawing function
            def draw_header(canvas, doc):
                width, height = A4
                self.create_header_background(canvas, width, height)
                
                # Title
                canvas.setFont("Helvetica-Bold", 20)
                canvas.setFillColor(colors.white)
                canvas.drawCentredText(width/2, height-50, "CIS BENCHMARK AUDIT REPORT")
                canvas.setFont("Helvetica", 12)
                canvas.drawCentredText(width/2, height-70, "Security Compliance Assessment")
                
                # Compliance percentage badge - Fixed to 2 decimal places
                total_checks = len(target.results)
                passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
                compliance_pct = round((passed_checks / total_checks * 100), 2) if total_checks > 0 else 0.00
                
                badge_x = width - 100
                badge_y = height - 80
                canvas.setFillColor(colors.Color(1, 1, 1, alpha=0.2))
                canvas.roundRect(badge_x, badge_y, 80, 40, 6, fill=1, stroke=0)
                canvas.setFillColor(colors.white)
                canvas.setFont("Helvetica-Bold", 16)
                canvas.drawCentredText(badge_x + 40, badge_y + 20, f"{self.format_percentage(compliance_pct)}%")
                canvas.setFont("Helvetica", 8)
                canvas.drawCentredText(badge_x + 40, badge_y + 8, "COMPLIANT")
            
            # Executive Summary
            story.append(Spacer(1, 20))
            story.append(Paragraph("EXECUTIVE SUMMARY", self.styles['SectionTitle']))
            
            # Metadata
            story.append(self.create_metadata_section(target))
            story.append(Spacer(1, 15))
            
            # Summary text - Fixed percentages to 2 decimal places
            total_checks = len(target.results)
            passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
            failed_checks = total_checks - passed_checks
            compliance_pct = round((passed_checks / total_checks * 100), 2) if total_checks > 0 else 0.00
            
            summary_text = f"""This security audit assessed <b>{total_checks}</b> controls on target system <b>{target.ip}</b> 
            using CIS benchmarks. The system achieved <b>{self.format_percentage(compliance_pct)}%</b> compliance with <b>{passed_checks}</b> controls 
            passing and <b>{failed_checks}</b> requiring remediation. This report provides detailed findings and 
            specific remediation guidance for all assessed controls."""
            
            story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
            story.append(Spacer(1, 15))
            
            # Summary table
            story.append(Paragraph("COMPLIANCE METRICS", self.styles['SectionTitle']))
            story.append(self.create_summary_table(target))
            story.append(Spacer(1, 20))
            
            # Risk assessment - Fixed percentages to 2 decimal places
            if failed_checks > 0:
                # Recalculate compliance_pct here to ensure consistency
                if total_checks > 0:
                    compliance_pct = (passed_checks / total_checks * 100)
                else:
                    compliance_pct = 0
                    
                risk_level = "HIGH" if compliance_pct < 70 else "MEDIUM" if compliance_pct < 85 else "LOW"
                risk_text = f"<b>Risk Assessment:</b> Based on {self.format_percentage(compliance_pct)}% compliance, this system presents {risk_level} security risk. Priority should be given to remediating the {failed_checks} non-compliant controls."
                story.append(Paragraph(risk_text, self.styles['ExecutiveSummary']))
                story.append(Spacer(1, 15))
            
            # Page break before detailed results
            story.append(PageBreak())
            
            # Detailed Results
            story.append(Paragraph("DETAILED ASSESSMENT RESULTS", self.styles['SectionTitle']))
            story.append(Spacer(1, 10))
            
            if target.results:
                # Create results table with proper text wrapping
                results_data = [
                    [
                        Paragraph('<b>Control</b>', self.styles['StatusText']),
                        Paragraph('<b>Status</b>', self.styles['StatusText']),
                        Paragraph('<b>Remediation</b>', self.styles['StatusText'])
                    ]
                ]
                
                for result in target.results:
                    status = result.get('status', 'UNKNOWN')
                    check = result.get('check', 'Unknown Check')
                    remediation = result.get('remediation', 'No remediation provided')
                    
                    # Format check with proper wrapping
                    check_text = self.wrap_text(check, 50)
                    check_paragraph = Paragraph(check_text, self.styles['CheckDescription'])
                    
                    # Status with color
                    status_color = self.colors['success'] if 'PASSED' in status else self.colors['danger']
                    status_style = ParagraphStyle(
                        'StatusColored',
                        parent=self.styles['StatusText'],
                        textColor=status_color
                    )
                    status_paragraph = Paragraph(f'<b>{status}</b>', status_style)
                    
                    # Remediation with proper wrapping
                    if 'PASSED' in status:
                        remediation_text = "Control is compliant"
                    else:
                        remediation_text = self.wrap_text(remediation, 60)
                    
                    remediation_paragraph = Paragraph(remediation_text, self.styles['RemediationText'])
                    
                    results_data.append([check_paragraph, status_paragraph, remediation_paragraph])
                
                # Create table with appropriate column widths
                results_table = Table(
                    results_data,
                    colWidths=[2.2*inch, 0.8*inch, 2.5*inch],
                    repeatRows=1
                )
                
                # Enhanced table styling
                table_style = [
                    # Header
                    ('BACKGROUND', (0, 0), (-1, 0), self.colors['primary']),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, 0), 8),
                    
                    # All cells
                    ('ALIGN', (0, 0), (0, -1), 'LEFT'),  # Control column left-aligned
                    ('ALIGN', (1, 0), (1, -1), 'CENTER'),  # Status column centered
                    ('ALIGN', (2, 0), (2, -1), 'LEFT'),  # Remediation column left-aligned
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, self.colors['gray_200']),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ]
                
                # Alternating row colors
                for i in range(1, len(results_data)):
                    if i % 2 == 0:
                        table_style.append(('BACKGROUND', (0, i), (-1, i), self.colors['gray_50']))
                
                results_table.setStyle(TableStyle(table_style))
                story.append(KeepTogether(results_table))
            
            # Footer disclaimer
            story.append(Spacer(1, 20))
            story.append(Paragraph("REPORT DISCLAIMER", self.styles['SectionTitle']))
            
            disclaimer = f"""This assessment was generated on {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} 
            using CIS benchmarks. Results represent a point-in-time evaluation and should be validated by security 
            professionals. Regular reassessments are recommended to maintain security posture."""
            
            story.append(Paragraph(disclaimer, self.styles['ExecutiveSummary']))
            
            # Build PDF
            def add_page_elements(canvas, doc):
                draw_header(canvas, doc)
                
                # Footer
                canvas.setFont("Helvetica", 7)
                canvas.setFillColor(self.colors['gray_500'])
                canvas.drawString(0.6*inch, 0.4*inch, f"CIS Audit Report - {target.ip}")
                canvas.drawRightString(A4[0] - 0.6*inch, 0.4*inch, f"Page {doc.page}")
                canvas.drawCentredText(A4[0]/2, 0.4*inch, 
                                     f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}")
            
            doc.build(story, onFirstPage=add_page_elements, onLaterPages=add_page_elements)
            logger.info(f"Professional PDF report generated: {output_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error generating PDF report: {str(e)}")
            return False

def generate_pdf_report(audit_id, target, reports_dir='reports'):
    """Main function to generate PDF report with datetime in filename"""
    try:
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename with datetime: ip_datetime.pdf
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip = target.ip.replace('.', '_').replace(':', '_')
        pdf_filename = os.path.join(reports_dir, f"{safe_ip}_{timestamp}.pdf")
        
        generator = ProfessionalPDFReportGenerator()
        success = generator.generate_pdf_report(target, pdf_filename)
        
        if success:
            return os.path.abspath(pdf_filename)
        else:
            return None
            
    except Exception as e:
        logger.error(f"Error in PDF report generation: {str(e)}")
        return None
