#!/usr/bin/env python3
import ansible_runner
import json
import os
import datetime
import shutil
import logging
from jinja2 import Environment, FileSystemLoader
import concurrent.futures
import threading
from typing import List, Dict, Any
import uuid

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/audit.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Thread-safe storage for audit results
audit_results_storage = {}
storage_lock = threading.Lock()

class AuditTarget:
    """Represents a single audit target"""
    def __init__(self, ip: str, username: str, key_path: str, os: str = "ubuntu", level: str = "level1"):
        self.ip = ip
        self.username = username
        self.key_path = key_path
        self.os = os.lower()
        self.level = level if os.lower() != "windows" else "default"
        self.audit_id = str(uuid.uuid4())
        self.results = []
        self.status = "pending"
        self.start_time = None
        self.end_time = None
        self.error_message = None

def parse_targets_file(file_path: str) -> List[AuditTarget]:
    """
    Parse targets file and return list of AuditTarget objects
    File format: IP USERNAME KEY_PATH OS [LEVEL]
    Example:
    192.168.1.100 ubuntu /path/to/key ubuntu level1
    192.168.1.101 administrator /path/to/key windows
    """
    targets = []
    
    if not os.path.exists(file_path):
        raise FileNotFoundError(f"Targets file not found: {file_path}")
    
    with open(file_path, 'r') as f:
        for line_num, line in enumerate(f, 1):
            line = line.strip()
            if not line or line.startswith('#'):
                continue
                
            parts = line.split()
            if len(parts) < 4:  # Now requires OS field
                logger.warning(f"Invalid line {line_num} in targets file: {line}")
                continue
                
            ip = parts[0]
            username = parts[1]
            key_path = parts[2]
            os_type = parts[3]
            level = parts[4] if len(parts) > 4 else ("level1" if os_type.lower() != "windows" else "default")
            
            targets.append(AuditTarget(ip, username, key_path, os_type, level))
    
    logger.info(f"Parsed {len(targets)} targets from {file_path}")
    return targets

def run_audit_single(target: AuditTarget) -> AuditTarget:
    """
    Execute Ansible playbook for CIS audit on a single target
    """
    logger.info(f"Starting audit for {target.ip} with OS {target.os} and level {target.level}")
    target.start_time = datetime.datetime.now()
    target.status = "running"
    
    # Store initial status
    with storage_lock:
        audit_results_storage[target.audit_id] = target
    
    try:
        # Get absolute base directory of this file
        base_dir = os.path.dirname(os.path.abspath(__file__))
        playbooks_dir = os.path.join(base_dir, 'playbooks')

        # Create playbooks directory if it doesn't exist
        if not os.path.isdir(playbooks_dir):
            os.makedirs(playbooks_dir, exist_ok=True)
            logger.warning(f"Created playbooks directory: {playbooks_dir}")

        # Select playbook based on OS and level
        if target.os.lower() == "windows":
            playbook_filename = 'cis_audit_windows.yml'
        else:  # Default to ubuntu/linux
            playbook_filename = f'cis_audit_{target.level}.yml'
        
        playbook_path = os.path.join(playbooks_dir, playbook_filename)

        # Check if playbook exists, if not try to find it in current directory
        if not os.path.isfile(playbook_path):
            # Try current directory
            current_dir_playbook = os.path.join(base_dir, playbook_filename)
            if os.path.isfile(current_dir_playbook):
                playbook_path = current_dir_playbook
            else:
                raise Exception(f"Playbook not found: {playbook_filename} (looked in {playbooks_dir} and {base_dir})")

        # Create temporary directory for ansible-runner
        runner_dir = os.path.join(base_dir, f'runner_temp_{target.audit_id}')
        if os.path.exists(runner_dir):
            shutil.rmtree(runner_dir)
        os.makedirs(runner_dir, exist_ok=True)

        try:
            # Create inventory
            inventory_dir = os.path.join(runner_dir, 'inventory')
            os.makedirs(inventory_dir, exist_ok=True)
            
            with open(os.path.join(inventory_dir, 'hosts'), 'w') as f:
                f.write(f"[servers]\n{target.ip}\n")

            # Ansible variables - different for Windows
            if target.os.lower() == "windows":
                extravars = {
                    'ansible_user': target.username,
                    'ansible_ssh_private_key_file': target.key_path,
                    'ansible_host_key_checking': False,
                    'ansible_ssh_common_args': '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null',
                    'ansible_connection': 'ssh',  # Using SSH for Windows too (OpenSSH)
                    'ansible_shell_type': 'powershell'
                }
            else:
                extravars = {
                    'ansible_user': target.username,
                    'ansible_ssh_private_key_file': target.key_path,
                    'ansible_host_key_checking': False,
                    'ansible_ssh_common_args': '-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null'
                }

            logger.info(f"Running Ansible playbook: {playbook_path}")
            
            # Execute playbook
            r = ansible_runner.run(
                private_data_dir=runner_dir,
                playbook=playbook_path,
                extravars=extravars,
                quiet=False,
                verbosity=1
            )

            # Parse results
            target.results = parse_ansible_results(r)
            
            # If no results were parsed, add a summary based on ansible run status
            if not target.results:
                if r.status == 'successful':
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'PASSED',
                        'remediation': 'Playbook executed successfully but no specific CIS checks were detected'
                    }]
                elif r.status == 'failed':
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'FAILED',
                        'remediation': f'Playbook execution failed. Check logs for details.'
                    }]
                else:
                    target.results = [{
                        'check': 'Ansible Execution',
                        'status': 'FAILED',
                        'remediation': f'Playbook execution status: {r.status}'
                    }]
            
            target.status = "completed"
            target.end_time = datetime.datetime.now()
            
            logger.info(f"Audit completed for {target.ip} with {len(target.results)} checks")

        finally:
            # Cleanup
            if os.path.exists(runner_dir):
                try:
                    shutil.rmtree(runner_dir)
                except Exception as cleanup_error:
                    logger.warning(f"Could not cleanup temp directory: {cleanup_error}")

    except Exception as e:
        logger.error(f"Error during audit for {target.ip}: {str(e)}")
        target.status = "failed"
        target.error_message = str(e)
        target.end_time = datetime.datetime.now()
        target.results = [{
            'check': 'Execution Error',
            'status': 'FAILED',
            'remediation': f'Error: {str(e)}'
        }]
    
    # Update storage
    with storage_lock:
        audit_results_storage[target.audit_id] = target
    
    return target

def run_audit_batch(targets_file: str, max_workers: int = 5) -> Dict[str, Any]:
    """
    Execute audits on multiple targets concurrently
    """
    try:
        targets = parse_targets_file(targets_file)
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'targets': []
        }
    
    if not targets:
        return {
            'success': False,
            'error': 'No valid targets found',
            'targets': []
        }
    
    batch_id = str(uuid.uuid4())
    logger.info(f"Starting batch audit {batch_id} with {len(targets)} targets")
    
    # Execute audits concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {executor.submit(run_audit_single, target): target for target in targets}
        
        completed_targets = []
        for future in concurrent.futures.as_completed(future_to_target):
            try:
                target = future.result()
                completed_targets.append(target)
            except Exception as e:
                logger.error(f"Error in batch audit thread: {str(e)}")
                # Create a failed target for this error
                failed_target = AuditTarget("unknown", "unknown", "unknown")
                failed_target.status = "failed"
                failed_target.error_message = str(e)
                failed_target.results = [{
                    'check': 'Thread Execution Error',
                    'status': 'FAILED',
                    'remediation': f'Error: {str(e)}'
                }]
                completed_targets.append(failed_target)
    
    # Generate summary
    total_targets = len(completed_targets)
    successful_targets = len([t for t in completed_targets if t.status == "completed"])
    failed_targets = total_targets - successful_targets
    
    result = {
        'success': True,
        'batch_id': batch_id,
        'summary': {
            'total_targets': total_targets,
            'successful': successful_targets,
            'failed': failed_targets
        },
        'targets': []
    }
    
    # Add target details
    for target in completed_targets:
        target_info = {
            'audit_id': target.audit_id,
            'ip': target.ip,
            'username': target.username,
            'os': target.os,
            'level': target.level,
            'status': target.status,
            'start_time': target.start_time.isoformat() if target.start_time else None,
            'end_time': target.end_time.isoformat() if target.end_time else None,
            'duration': str(target.end_time - target.start_time) if target.start_time and target.end_time else None,
            'error_message': target.error_message,
            'results_count': len(target.results),
            'passed_checks': len([r for r in target.results if 'PASSED' in r['status']]),
            'failed_checks': len([r for r in target.results if 'FAILED' in r['status']])
        }
        result['targets'].append(target_info)
    
    logger.info(f"Batch audit {batch_id} completed: {successful_targets}/{total_targets} successful")
    return result

def get_audit_results(audit_id: str) -> Dict[str, Any]:
    """Get results for a specific audit"""
    with storage_lock:
        target = audit_results_storage.get(audit_id)
    
    if not target:
        return {'success': False, 'error': 'Audit not found'}
    
    return {
        'success': True,
        'audit_id': audit_id,
        'ip': target.ip,
        'os': target.os,
        'status': target.status,
        'results': target.results,
        'summary': {
            'total_checks': len(target.results),
            'passed_checks': len([r for r in target.results if 'PASSED' in r['status']]),
            'failed_checks': len([r for r in target.results if 'FAILED' in r['status']])
        }
    }

def generate_report_html(audit_id: str) -> str:
    """
    Generate HTML report for a specific audit with datetime in filename
    """
    logger.info(f"Generating HTML report for audit ID: {audit_id}")
    
    with storage_lock:
        target = audit_results_storage.get(audit_id)
    
    if not target:
        logger.error(f"Audit {audit_id} not found in storage")
        return None
    
    if not target.results:
        logger.warning(f"No results available for audit {audit_id}")
        target.results = [{
            'check': 'No Results',
            'status': 'FAILED',
            'remediation': 'Audit completed but no results were captured'
        }]

    try:
        # Ensure reports directory exists
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename with datetime: ip_datetime.html
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip = target.ip.replace('.', '_').replace(':', '_')
        report_filename = os.path.join(reports_dir, f"{safe_ip}_{timestamp}.html")
        
        # Check for template file
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_file = os.path.join(current_dir, 'report_template.html')
        
        if not os.path.isfile(template_file):
            logger.warning(f"Template file not found at {template_file}, creating basic HTML report")
            html_content = generate_basic_html_report(target)
        else:
            with open(template_file, 'r', encoding='utf-8') as f:
                template_content = f.read()
            
            html_content = process_template(template_content, target)
        
        # Write the report file
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)

        logger.info(f"HTML report generated successfully: {report_filename}")
        return os.path.abspath(report_filename)

    except Exception as e:
        logger.error(f"Error generating HTML report for {audit_id}: {str(e)}")
        return None

def generate_report_pdf(audit_id: str) -> str:
    """
    Generate PDF report for a specific audit with datetime in filename
    """
    logger.info(f"Generating PDF report for audit ID: {audit_id}")
    
    with storage_lock:
        target = audit_results_storage.get(audit_id)
    
    if not target:
        logger.error(f"Audit {audit_id} not found in storage")
        return None
    
    if not target.results:
        logger.warning(f"No results available for audit {audit_id}")
        target.results = [{
            'check': 'No Results',
            'status': 'FAILED',
            'remediation': 'Audit completed but no results were captured'
        }]

    try:
        # Check if reportlab is available
        try:
            import reportlab
            from reportlab.lib import colors
            from reportlab.lib.pagesizes import A4
            logger.info(f"ReportLab available - version: {reportlab.Version}")
        except ImportError as e:
            logger.error(f"ReportLab not available: {e}")
            return None
        
        # Try importing the professional PDF generator
        try:
            from pdf_generator import generate_pdf_report
            logger.info("Professional PDF generator available")
            use_professional = True
        except ImportError as e:
            logger.warning(f"Professional PDF generator not available: {e}")
            use_professional = False
        
        # Ensure reports directory exists
        reports_dir = 'reports'
        os.makedirs(reports_dir, exist_ok=True)
        
        # Generate filename with datetime: ip_datetime.pdf
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        safe_ip = target.ip.replace('.', '_').replace(':', '_')
        
        if use_professional:
            # Use the professional PDF generator
            pdf_path = generate_pdf_report(audit_id, target, reports_dir)
            
            if pdf_path and os.path.exists(pdf_path):
                logger.info(f"Professional PDF report generated successfully: {pdf_path}")
                return pdf_path
            else:
                logger.error(f"Professional PDF generation failed for audit {audit_id}")
                use_professional = False
        
        if not use_professional:
            # Use basic PDF generation as fallback
            from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import inch
            
            pdf_filename = os.path.join(reports_dir, f"{safe_ip}_{timestamp}.pdf")
            
            # Create basic PDF document
            doc = SimpleDocTemplate(pdf_filename, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            story.append(Paragraph(f"CIS Audit Report - {target.ip}", styles['Title']))
            story.append(Spacer(1, 20))
            
            # Basic info with better formatting
            info_data = [
                ['Target IP:', target.ip],
                ['Operating System:', target.os.upper()],
                ['Audit Level:', target.level.upper()],
                ['Report Generated:', datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
                ['Status:', target.status.upper()]
            ]
            
            info_table = Table(info_data, colWidths=[2*inch, 3*inch])
            info_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 0), (-1, -1), 10),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ]))
            story.append(info_table)
            story.append(Spacer(1, 30))
            
            # Summary
            total_checks = len(target.results)
            passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
            failed_checks = total_checks - passed_checks
            compliance_pct = round((passed_checks/total_checks*100), 1) if total_checks > 0 else 0
            
            summary_data = [
                ['Summary Metric', 'Count', 'Percentage'],
                ['Total Checks', str(total_checks), '100%'],
                ['Passed Checks', str(passed_checks), f"{compliance_pct:.2f}%"],
                ['Failed Checks', str(failed_checks), f"{(100-compliance_pct):.2f}%"],
                ['Compliance Rate', f"{passed_checks}/{total_checks}", f"{compliance_pct:.2f}%"],
            ]
            
            summary_table = Table(summary_data, colWidths=[2.5*inch, 1.5*inch, 1.5*inch])
            summary_table.setStyle(TableStyle([
                # Header
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                
                # Body
                ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                ('FONTSIZE', (0, 1), (-1, -1), 9),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 1), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.lightgrey]),
            ]))
            
            story.append(summary_table)
            story.append(Spacer(1, 30))
            
            # Results table with better text wrapping
            if target.results:
                story.append(Paragraph("Detailed Results", styles['Heading2']))
                story.append(Spacer(1, 10))
                
                results_data = [['Control', 'Status', 'Remediation']]
                
                for result in target.results:
                    check = result.get('check', 'Unknown Check')
                    status = result.get('status', 'UNKNOWN')
                    remediation = result.get('remediation', 'No remediation provided')
                    
                    # Wrap long text to prevent overflow
                    if len(check) > 60:
                        check = check[:57] + "..."
                    
                    if len(remediation) > 80 and 'FAILED' in status:
                        remediation = remediation[:77] + "..."
                    elif 'PASSED' in status:
                        remediation = "Control is compliant"
                    
                    results_data.append([
                        Paragraph(check, styles['Normal']),
                        Paragraph(status, styles['Normal']),
                        Paragraph(remediation, styles['Normal'])
                    ])
                
                results_table = Table(results_data, colWidths=[2.2*inch, 1*inch, 2.3*inch], repeatRows=1)
                results_table.setStyle(TableStyle([
                    # Header
                    ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 9),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 8),
                    ('TOPPADDING', (0, 0), (-1, 0), 8),
                    
                    # Body
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 8),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('TOPPADDING', (0, 1), (-1, -1), 4),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 4),
                    ('LEFTPADDING', (0, 0), (-1, -1), 4),
                    ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ]))
                
                # Color code status column
                for i, result in enumerate(target.results, 1):
                    if 'PASSED' in result.get('status', ''):
                        results_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.green)
                        ]))
                    elif 'FAILED' in result.get('status', ''):
                        results_table.setStyle(TableStyle([
                            ('TEXTCOLOR', (1, i), (1, i), colors.red)
                        ]))
                
                story.append(results_table)
            
            # Build the PDF
            doc.build(story)
            
            logger.info(f"Basic PDF report generated successfully: {pdf_filename}")
            return os.path.abspath(pdf_filename)
            
    except Exception as e:
        logger.error(f"Error generating PDF report for {audit_id}: {str(e)}")
        logger.error(f"Exception details: {type(e).__name__}: {str(e)}")
        return None

def generate_basic_html_report(target):
    """Generate a basic HTML report when template is not available"""
    total_checks = len(target.results)
    passed_checks = len([r for r in target.results if 'PASSED' in r['status']])
    failed_checks = total_checks - passed_checks
    compliance_pct = round((passed_checks / total_checks * 100), 1) if total_checks > 0 else 0
    
    results_html = ""
    for result in target.results:
        status_style = "color: #28a745;" if 'PASSED' in result['status'] else "color: #dc3545;"
        remediation = result.get('remediation', 'No remediation provided') if 'FAILED' in result['status'] else 'No action required'
        
        results_html += f"""
        <tr>
            <td>{result.get('check', 'Unknown Check')}</td>
            <td style="{status_style} font-weight: bold;">{result.get('status', 'UNKNOWN')}</td>
            <td>{remediation}</td>
        </tr>
        """
    
    return f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>CIS Audit Report - {target.ip}</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            .header {{ background: #f8f9fa; padding: 20px; border-radius: 5px; margin-bottom: 20px; }}
            .summary {{ display: flex; gap: 20px; margin: 20px 0; }}
            .summary-card {{ background: #fff; border: 1px solid #ddd; padding: 15px; border-radius: 5px; text-align: center; flex: 1; }}
            table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
            th, td {{ border: 1px solid #ddd; padding: 10px; text-align: left; }}
            th {{ background: #f8f9fa; }}
            .progress {{ background: #e9ecef; height: 20px; border-radius: 10px; overflow: hidden; margin: 10px 0; }}
            .progress-bar {{ height: 100%; background: #28a745; color: white; text-align: center; line-height: 20px; }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>CIS Audit Report</h1>
            <p><strong>Target:</strong> {target.ip}</p>
            <p><strong>OS:</strong> {target.os}</p>
            <p><strong>Level:</strong> {target.level}</p>
            <p><strong>Generated:</strong> {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        </div>
        
        <div class="summary">
            <div class="summary-card">
                <h3>{total_checks}</h3>
                <p>Total Checks</p>
            </div>
            <div class="summary-card">
                <h3>{passed_checks}</h3>
                <p>Passed</p>
            </div>
            <div class="summary-card">
                <h3>{failed_checks}</h3>
                <p>Failed</p>
            </div>
        </div>
        
        <div class="progress">
            <div class="progress-bar" style="width: {compliance_pct}%">{compliance_pct}% Compliant</div>
        </div>
        
        <h2>Detailed Results</h2>
        <table>
            <thead>
                <tr>
                    <th>Check</th>
                    <th>Status</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {results_html}
            </tbody>
        </table>
        
        <div style="margin-top: 40px; text-align: center; color: #666;">
            <p>Generated by CIS Auditor Tool</p>
        </div>
    </body>
    </html>
    """

def process_template(template_content, target):
    """Process the template with target data - Enhanced for professional template"""
    total_checks = len(target.results)
    passed_checks = len([r for r in target.results if 'PASSED' in r['status']])
    failed_checks = total_checks - passed_checks
    duration_str = str(target.end_time - target.start_time).split('.')[0] if target.start_time and target.end_time else "N/A"
    compliance_pct = round((passed_checks / total_checks * 100), 1) if total_checks > 0 else 0
    
    # Replace template variables
    html_output = template_content.replace('{{ target_ip }}', target.ip)
    html_output = html_output.replace('{{ audit_level }}', target.level.upper())
    html_output = html_output.replace('{{ date_time }}', datetime.datetime.now().strftime("%B %d, %Y at %H:%M:%S"))
    html_output = html_output.replace('{{ duration }}', duration_str)
    html_output = html_output.replace('{{ total_checks }}', str(total_checks))
    html_output = html_output.replace('{{ passed_checks }}', str(passed_checks))
    html_output = html_output.replace('{{ failed_checks }}', str(failed_checks))
    html_output = html_output.replace('{{ compliance_percentage }}', str(compliance_pct))
    
    # Build results table rows with enhanced styling
    results_rows = ""
    for result in target.results:
        status_class = "result-failed" if 'FAILED' in result['status'] else "result-passed"
        badge_class = "status-failed" if 'FAILED' in result['status'] else "status-passed"
        
        # Enhanced check ID formatting
        check_content = f'<div class="check-id">{result.get("check", "Unknown Check")}</div>'
        
        # Enhanced remediation formatting
        if 'FAILED' in result['status'] and result.get('remediation'):
            remediation_html = f'<div class="remediation">{result.get("remediation", "")}</div>'
        else:
            remediation_html = '<div class="no-remediation">Control is compliant</div>'
        
        results_rows += f'''
            <tr class="result-row {status_class}">
                <td>{check_content}</td>
                <td><span class="status-badge {badge_class}">{result.get('status', 'UNKNOWN')}</span></td>
                <td>{remediation_html}</td>
            </tr>
        '''
    
    # Replace the results_rows placeholder
    html_output = html_output.replace('{{ results_rows }}', results_rows)
    
    return html_output

def generate_batch_report(batch_result: Dict[str, Any]) -> str:
    """Generate a summary report for batch audit with datetime in filename"""
    try:
        timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        batch_id = batch_result.get('batch_id', 'unknown')
        
        os.makedirs('reports', exist_ok=True)
        # Updated filename format: batch_batchid_datetime.html
        report_filename = f"reports/batch_{batch_id[:8]}_{timestamp}.html"
        
        # Create batch report HTML
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>Batch Audit Report - {timestamp}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .header {{ background: #1a365d; color: white; padding: 20px; margin-bottom: 20px; }}
                .summary {{ background: #f0f0f0; padding: 15px; margin: 10px 0; border-radius: 5px; }}
                .target {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; border-radius: 5px; }}
                .success {{ border-left: 4px solid #38a169; background: #f0fff4; }}
                .failed {{ border-left: 4px solid #e53e3e; background: #fff5f5; }}
                .metadata {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin: 15px 0; }}
                .metadata-item {{ background: white; padding: 10px; border: 1px solid #e5e7eb; border-radius: 4px; }}
                .metadata-label {{ font-size: 0.875rem; color: #6b7280; text-transform: uppercase; }}
                .metadata-value {{ font-size: 1.125rem; font-weight: 600; color: #374151; }}
            </style>
        </head>
        <body>
            <div class="header">
                <h1>Batch Audit Report</h1>
                <p>Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                <p>Batch ID: {batch_id}</p>
            </div>
            
            <div class="summary">
                <h2>Summary</h2>
                <div class="metadata">
                    <div class="metadata-item">
                        <div class="metadata-label">Total Targets</div>
                        <div class="metadata-value">{batch_result['summary']['total_targets']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Successful</div>
                        <div class="metadata-value">{batch_result['summary']['successful']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Failed</div>
                        <div class="metadata-value">{batch_result['summary']['failed']}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Success Rate</div>
                        <div class="metadata-value">{round((batch_result['summary']['successful'] / batch_result['summary']['total_targets'] * 100), 1) if batch_result['summary']['total_targets'] > 0 else 0}%</div>
                    </div>
                </div>
            </div>
            
            <h2>Target Details</h2>
        """
        
        for target in batch_result['targets']:
            status_class = 'success' if target['status'] == 'completed' else 'failed'
            html_content += f"""
            <div class="target {status_class}">
                <h3>{target['ip']} ({target['os'].upper()})</h3>
                <div class="metadata">
                    <div class="metadata-item">
                        <div class="metadata-label">Status</div>
                        <div class="metadata-value">{target['status'].upper()}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Level</div>
                        <div class="metadata-value">{target['level'].upper()}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Duration</div>
                        <div class="metadata-value">{target.get('duration', 'N/A')}</div>
                    </div>
                    <div class="metadata-item">
                        <div class="metadata-label">Results</div>
                        <div class="metadata-value">✓ {target['passed_checks']} | ✗ {target['failed_checks']}</div>
                    </div>
                </div>
                {f"<p style='color: #e53e3e; font-weight: 600;'>Error: {target['error_message']}</p>" if target.get('error_message') else ""}
            </div>
            """
        
        html_content += """
            <div style="margin-top: 40px; text-align: center; padding: 20px; background: #f9fafb; border-radius: 5px;">
                <p style="color: #6b7280;">Generated by CIS Auditor Tool</p>
            </div>
        </body>
        </html>
        """
        
        with open(report_filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logger.info(f"Batch report generated: {report_filename}")
        return report_filename
        
    except Exception as e:
        logger.error(f"Error generating batch report: {str(e)}")
        return None

def parse_ansible_results(ansible_run):
    """
    Parse Ansible runner results to extract CIS check outcomes
    """
    results = []
    current_check = None
    check_results = {}

    try:
        for event in ansible_run.events:
            event_type = event.get('event')
            event_data = event.get('event_data', {})
            task_name = event_data.get('task', '')

            # Detect CIS check tasks
            if 'CIS' in task_name and 'Check' in task_name and 'Result:' not in task_name:
                current_check = task_name
                check_results[current_check] = {'status': 'UNKNOWN', 'remediation': ''}
                continue

            # Process result tasks
            if current_check and 'CIS' in task_name and 'Result:' in task_name:
                if 'Pass' in task_name:
                    if event_type == 'runner_on_ok':
                        check_results[current_check] = {
                            'status': 'PASSED',
                            'remediation': ''
                        }
                elif 'Fail' in task_name:
                    if event_type == 'runner_on_failed':
                        remediation = event_data.get('res', {}).get('msg', 'No remediation provided')
                        check_results[current_check] = {
                            'status': 'FAILED',
                            'remediation': remediation
                        }

        # Convert to final results
        for check_name, result in check_results.items():
            if result['status'] != 'UNKNOWN':
                results.append({
                    'check': check_name,
                    'status': result['status'],
                    'remediation': result['remediation']
                })

        # Handle connection issues
        if ansible_run.status == 'unreachable':
            results.append({
                'check': 'Host Connectivity',
                'status': 'FAILED',
                'remediation': 'Could not connect to host. Check IP, SSH access, and key file.'
            })
        elif ansible_run.status == 'failed' and not results:
            # If the run failed but we didn't capture any specific checks
            results.append({
                'check': 'Playbook Execution',
                'status': 'FAILED',
                'remediation': f'Playbook failed to execute. Status: {ansible_run.status}'
            })

    except Exception as e:
        logger.error(f"Error parsing ansible results: {str(e)}")
        results.append({
            'check': 'Result Parsing Error',
            'status': 'FAILED',
            'remediation': f'Error parsing results: {str(e)}'
        })

    return results

# Legacy function for backward compatibility
def run_audit(host_ip, username, key_path, level, os_type="ubuntu"):
    """Legacy single audit function for backward compatibility"""
    target = AuditTarget(host_ip, username, key_path, os_type, level)
    completed_target = run_audit_single(target)
    return completed_target.results

# Keep global variable for backward compatibility
audit_results = []

def get_legacy_audit_results():
    """Return current audit results (legacy function)"""
    return audit_results
