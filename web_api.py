#!/usr/bin/env python3
"""
CIS Auditor Web API
Flask-based REST API for web and mobile integration
Enhanced with better PDF error handling and dependency checking
"""

from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
import os
import tempfile
import threading
import time
import json
from datetime import datetime, timedelta
from werkzeug.utils import secure_filename
import logging
import subprocess
import sys

# Import your enhanced API
from api import (run_audit_batch, get_audit_results, generate_report_html, 
                generate_report_pdf, audit_results_storage, storage_lock, 
                AuditTarget, run_audit_single)

app = Flask(__name__)
CORS(app)  # Enable CORS for web/mobile integration

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
UPLOAD_FOLDER = 'uploads'
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
ALLOWED_EXTENSIONS = {'txt'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs('reports', exist_ok=True)
os.makedirs('logs', exist_ok=True)

# In-memory storage for scheduling (in production, use a database)
scheduled_audits = {}
schedule_lock = threading.Lock()

# PDF generation status tracking
pdf_capability = None

def check_pdf_dependencies():
    """
    Check if PDF generation dependencies are available and working
    """
    global pdf_capability
    
    if pdf_capability is not None:
        return pdf_capability
    
    try:
        # Check for reportlab
        import reportlab
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import SimpleDocTemplate
        
        logger.info(f"ReportLab found - version: {reportlab.Version}")
        
        # Check for pdf_generator.py
        current_dir = os.path.dirname(os.path.abspath(__file__))
        pdf_generator_path = os.path.join(current_dir, 'pdf_generator.py')
        
        if os.path.exists(pdf_generator_path):
            try:
                import pdf_generator
                if hasattr(pdf_generator, 'generate_pdf_report'):
                    logger.info("PDF generation fully available (reportlab + pdf_generator)")
                    pdf_capability = {'status': 'full', 'message': 'Full PDF generation available'}
                else:
                    logger.warning("pdf_generator.py exists but missing generate_pdf_report function")
                    pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
            except ImportError as e:
                logger.warning(f"pdf_generator.py exists but import failed: {e}")
                pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
        else:
            logger.warning("pdf_generator.py not found, using basic PDF generation")
            pdf_capability = {'status': 'basic', 'message': 'Basic PDF generation available'}
            
    except ImportError as e:
        logger.error(f"ReportLab not available: {e}")
        pdf_capability = {'status': 'none', 'message': f'PDF generation not available: {str(e)}'}
    
    return pdf_capability

def install_reportlab():
    """
    Attempt to install reportlab automatically
    """
    try:
        logger.info("Attempting to install reportlab...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "reportlab"])
        logger.info("ReportLab installed successfully")
        # Reset capability check
        global pdf_capability
        pdf_capability = None
        return True
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to install reportlab: {e}")
        return False
    except Exception as e:
        logger.error(f"Error during reportlab installation: {e}")
        return False

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# API Endpoints

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint with PDF capability status"""
    pdf_status = check_pdf_dependencies()
    
    return jsonify({
        'status': 'healthy',
        'version': '2.1.0',
        'message': 'CIS Auditor API is running',
        'capabilities': {
            'pdf_generation': pdf_status
        }
    })

@app.route('/api/pdf-status', methods=['GET'])
def pdf_status():
    """Get detailed PDF generation capability status"""
    pdf_status = check_pdf_dependencies()
    
    recommendations = []
    if pdf_status['status'] == 'none':
        recommendations.append("Install reportlab: pip install reportlab")
    elif pdf_status['status'] == 'basic':
        recommendations.append("For enhanced PDF reports, ensure pdf_generator.py is present")
    
    return jsonify({
        'pdf_capability': pdf_status,
        'recommendations': recommendations
    })

@app.route('/api/install-pdf', methods=['POST'])
def install_pdf_dependencies():
    """Attempt to install PDF dependencies"""
    if request.json and request.json.get('confirm') == True:
        success = install_reportlab()
        if success:
            # Re-check capabilities
            pdf_status = check_pdf_dependencies()
            return jsonify({
                'success': True,
                'message': 'PDF dependencies installed successfully',
                'new_capability': pdf_status
            })
        else:
            return jsonify({
                'success': False,
                'message': 'Failed to install PDF dependencies. Please install manually: pip install reportlab'
            }), 500
    else:
        return jsonify({
            'error': 'Installation confirmation required',
            'required_payload': {'confirm': True}
        }), 400

@app.route('/api/audit/run', methods=['POST'])
def audit_single():
    """Run audit on a single target"""
    try:
        data = request.get_json()
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        required_fields = ['ip', 'username', 'key', 'os']
        missing_fields = [field for field in required_fields if field not in data]
        if missing_fields:
            return jsonify({'error': f'Missing required fields: {", ".join(missing_fields)}'}), 400
        
        # Map frontend values to backend format
        os_type = data['os'].lower()
        if os_type == 'linux':
            os_type = 'ubuntu'  # Default Linux to ubuntu
        
        level = data.get('level', 'L1')
        if level == 'Level 1':
            level = 'level1'
        elif level == 'Level 2':
            level = 'level2'
        elif level == 'L1':
            level = 'level1'
        elif level == 'L2':
            level = 'level2'
        
        # Create audit target
        target = AuditTarget(
            ip=data['ip'],
            username=data['username'],
            key_path=data['key'],
            os=os_type,
            level=level
        )
        
        # Start audit in background thread
        def run_audit_async():
            run_audit_single(target)
        
        thread = threading.Thread(target=run_audit_async)
        thread.start()
        
        return jsonify({
            'success': True,
            'audit': {
                'id': target.audit_id,
                'ip': target.ip,
                'os': target.os,
                'level': target.level,
                'status': 'running'
            }
        })
        
    except Exception as e:
        logger.error(f"Single audit error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/batch', methods=['POST'])
def audit_batch():
    """Run batch audit from uploaded targets file"""
    try:
        # Check if file was uploaded
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Only .txt files allowed'}), 400
        
        # Get optional parameters
        max_workers = request.form.get('workers', 5, type=int)
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        logger.info(f"Starting batch audit from file: {unique_filename}")
        
        # Run batch audit in background
        def run_batch_async():
            result = run_audit_batch(filepath, max_workers=max_workers)
            # Cleanup uploaded file
            try:
                os.remove(filepath)
            except:
                pass
        
        thread = threading.Thread(target=run_batch_async)
        thread.start()
        
        return jsonify({
            'success': True,
            'batch_file': filename,
            'total_created': 'Processing...',
            'message': 'Batch audit started successfully'
        })
            
    except Exception as e:
        logger.error(f"Batch audit error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audits/active', methods=['GET'])
def list_active_audits():
    """List all audits with enhanced data for the web UI"""
    try:
        with storage_lock:
            audits = []
            for audit_id, target in audit_results_storage.items():
                # Calculate summary statistics
                passed_checks = len([r for r in target.results if 'PASSED' in r.get('status', '')])
                failed_checks = len([r for r in target.results if 'FAILED' in r.get('status', '')])
                
                # Calculate duration
                duration = "N/A"
                if target.start_time:
                    if target.end_time:
                        duration_delta = target.end_time - target.start_time
                        duration = str(duration_delta).split('.')[0]  # Remove microseconds
                    else:
                        duration_delta = datetime.now() - target.start_time
                        duration = f"{str(duration_delta).split('.')[0]} (running)"
                
                # Format start time
                start_time_str = target.start_time.strftime('%Y-%m-%d %H:%M:%S') if target.start_time else 'N/A'
                
                audit_data = {
                    'id': audit_id,
                    'target': target.ip,
                    'os': target.os.title(),  # Capitalize for display
                    'level': target.level.upper() if target.level != 'default' else 'Default',
                    'status': target.status,
                    'start_time': start_time_str,
                    'duration': duration,
                    'summary': {
                        'passed': passed_checks,
                        'failed': failed_checks,
                        'total': len(target.results)
                    }
                }
                audits.append(audit_data)
        
        # Sort by start time, newest first
        audits.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        
        return jsonify({'audits': audits})
        
    except Exception as e:
        logger.error(f"List active audits error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/<audit_id>/status', methods=['GET'])
def get_audit_status(audit_id):
    """Get status and results of a specific audit"""
    try:
        result = get_audit_results(audit_id)
        
        if result['success']:
            return jsonify(result)
        else:
            return jsonify(result), 404
            
    except Exception as e:
        logger.error(f"Get audit status error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/audit/<audit_id>/report', methods=['GET'])
def generate_audit_report(audit_id):
    """Generate and serve HTML/PDF report for a specific audit"""
    try:
        logger.info(f"Report requested for audit ID: {audit_id}")
        
        # First check if audit exists in storage
        with storage_lock:
            target = audit_results_storage.get(audit_id)
        
        if not target:
            logger.error(f"Audit {audit_id} not found in storage")
            return jsonify({'error': 'Audit not found'}), 404
        
        if target.status not in ['completed', 'failed']:
            logger.warning(f"Audit {audit_id} is not completed (status: {target.status})")
            return jsonify({'error': 'Audit is not yet completed'}), 400
        
        # Check if we want PDF format
        format_type = request.args.get('format', 'html')
        
        if format_type.lower() == 'pdf':
            # Check PDF capability first
            pdf_status = check_pdf_dependencies()
            
            if pdf_status['status'] == 'none':
                return jsonify({
                    'error': 'PDF generation not available', 
                    'details': pdf_status['message'],
                    'solution': 'Install reportlab: pip install reportlab'
                }), 501  # Not Implemented
            
            # Generate PDF report
            try:
                pdf_path = generate_report_pdf(audit_id)
                
                if pdf_path and os.path.exists(pdf_path):
                    logger.info(f"PDF report generated successfully at: {pdf_path}")
                    
                    # Return PDF file
                    return send_file(pdf_path, 
                                   as_attachment=True, 
                                   download_name=f"audit_report_{target.ip}_{audit_id[:8]}.pdf",
                                   mimetype='application/pdf')
                else:
                    # PDF generation failed, but we can offer alternatives
                    error_response = {
                        'error': 'PDF report generation failed',
                        'pdf_status': pdf_status,
                        'alternatives': {
                            'html_report': f'/api/audit/{audit_id}/report?format=html'
                        }
                    }
                    
                    if pdf_status['status'] == 'basic':
                        error_response['suggestion'] = 'PDF generation may be limited. Consider adding pdf_generator.py for enhanced reports.'
                    
                    return jsonify(error_response), 500
                    
            except Exception as pdf_error:
                logger.error(f"PDF generation exception: {str(pdf_error)}")
                return jsonify({
                    'error': 'PDF generation encountered an error',
                    'details': str(pdf_error),
                    'pdf_status': pdf_status,
                    'alternatives': {
                        'html_report': f'/api/audit/{audit_id}/report?format=html'
                    }
                }), 500
        
        else:
            # Generate HTML report (this should always work)
            try:
                html_path = generate_report_html(audit_id)
                
                if html_path and os.path.exists(html_path):
                    logger.info(f"HTML report generated successfully at: {html_path}")
                    
                    # Return HTML for viewing in browser
                    return send_file(html_path, as_attachment=False,
                                   mimetype='text/html')
                else:
                    logger.error(f"HTML report generation failed for audit {audit_id}")
                    return jsonify({'error': 'HTML report generation failed'}), 500
                    
            except Exception as html_error:
                logger.error(f"HTML generation exception: {str(html_error)}")
                return jsonify({
                    'error': 'HTML report generation failed',
                    'details': str(html_error)
                }), 500
            
    except Exception as e:
        logger.error(f"Generate report error: {str(e)}", exc_info=True)
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule', methods=['POST'])
def create_schedule():
    """Schedule an audit for later execution"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        date = request.form.get('date')
        time_str = request.form.get('time')
        
        if not date or not time_str:
            return jsonify({'error': 'Date and time are required'}), 400
        
        # Validate and parse datetime
        try:
            schedule_datetime = datetime.strptime(f"{date} {time_str}", "%Y-%m-%d %H:%M")
        except ValueError:
            return jsonify({'error': 'Invalid date or time format'}), 400
        
        # Check if the scheduled time is in the future
        if schedule_datetime <= datetime.now():
            return jsonify({'error': 'Scheduled time must be in the future'}), 400
        
        # Save the uploaded file
        filename = secure_filename(file.filename)
        timestamp = int(time.time())
        unique_filename = f"scheduled_{timestamp}_{filename}"
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(filepath)
        
        # Create schedule entry
        schedule_id = f"schedule_{timestamp}"
        with schedule_lock:
            scheduled_audits[schedule_id] = {
                'id': schedule_id,
                'target': filename,
                'file_path': filepath,
                'date': date,
                'time': time_str,
                'datetime': schedule_datetime,
                'status': 'scheduled',
                'created_at': datetime.now()
            }
        
        return jsonify({
            'success': True,
            'created': {
                'id': schedule_id,
                'target': filename,
                'scheduled_for': schedule_datetime.isoformat()
            }
        })
        
    except Exception as e:
        logger.error(f"Create schedule error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule', methods=['GET'])
def list_schedules():
    """List all scheduled audits"""
    try:
        with schedule_lock:
            schedules = []
            for schedule_id, schedule_data in scheduled_audits.items():
                schedules.append({
                    'id': schedule_data['id'],
                    'target': schedule_data['target'],
                    'date': schedule_data['date'],
                    'time': schedule_data['time'],
                    'status': schedule_data['status']
                })
        
        # Sort by scheduled datetime
        schedules.sort(key=lambda x: f"{x['date']} {x['time']}")
        
        return jsonify({'schedules': schedules})
        
    except Exception as e:
        logger.error(f"List schedules error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/schedule/<schedule_id>', methods=['DELETE'])
def delete_schedule(schedule_id):
    """Delete a scheduled audit"""
    try:
        with schedule_lock:
            if schedule_id in scheduled_audits:
                schedule_data = scheduled_audits[schedule_id]
                # Clean up the uploaded file
                try:
                    if os.path.exists(schedule_data['file_path']):
                        os.remove(schedule_data['file_path'])
                except:
                    pass
                
                del scheduled_audits[schedule_id]
                return jsonify({'deleted': True})
            else:
                return jsonify({'error': 'Schedule not found'}), 404
        
    except Exception as e:
        logger.error(f"Delete schedule error: {str(e)}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/upload-test', methods=['POST'])
def upload_test():
    """Test endpoint for file upload functionality"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Read and validate file content
        content = file.read().decode('utf-8')
        file.seek(0)  # Reset file pointer
        
        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.startswith('#')]
        
        valid_targets = []
        invalid_lines = []
        
        for i, line in enumerate(lines, 1):
            parts = line.split()
            if len(parts) >= 4:  # Now requires OS field
                os_type = parts[3].lower()
                level = parts[4] if len(parts) > 4 else ('level1' if os_type != 'windows' else 'default')
                
                valid_targets.append({
                    'ip': parts[0],
                    'username': parts[1],
                    'key_path': parts[2],
                    'os': os_type,
                    'level': level
                })
            else:
                invalid_lines.append(f"Line {i}: {line}")
        
        return jsonify({
            'success': True,
            'valid_targets': len(valid_targets),
            'targets': valid_targets,
            'invalid_lines': invalid_lines
        })
        
    except Exception as e:
        return jsonify({'error': f'File processing error: {str(e)}'}), 400

# Web UI Route
@app.route('/', methods=['GET'])
def web_interface():
    """Serve the web UI"""
    try:
        return send_file('web_ui.html')
    except FileNotFoundError:
        return jsonify({'error': 'Web UI file not found'}), 404

# Static file serving for any additional assets
@app.route('/static/<path:filename>')
def static_files(filename):
    """Serve static files"""
    return send_from_directory('static', filename)

# Background scheduler to check for scheduled audits
def schedule_checker():
    """Background thread to check and execute scheduled audits"""
    while True:
        try:
            current_time = datetime.now()
            to_execute = []
            
            with schedule_lock:
                for schedule_id, schedule_data in scheduled_audits.items():
                    if (schedule_data['status'] == 'scheduled' and 
                        schedule_data['datetime'] <= current_time):
                        to_execute.append((schedule_id, schedule_data))
            
            # Execute scheduled audits
            for schedule_id, schedule_data in to_execute:
                try:
                    logger.info(f"Executing scheduled audit: {schedule_id}")
                    
                    # Update status
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'running'
                    
                    # Run the audit
                    result = run_audit_batch(schedule_data['file_path'], max_workers=3)
                    
                    # Update status and cleanup
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'completed'
                        # Clean up file
                        try:
                            os.remove(schedule_data['file_path'])
                        except:
                            pass
                    
                    logger.info(f"Scheduled audit completed: {schedule_id}")
                    
                except Exception as e:
                    logger.error(f"Error executing scheduled audit {schedule_id}: {str(e)}")
                    with schedule_lock:
                        scheduled_audits[schedule_id]['status'] = 'failed'
            
        except Exception as e:
            logger.error(f"Schedule checker error: {str(e)}")
        
        # Check every minute
        time.sleep(60)

# Start background scheduler
def start_scheduler():
    scheduler_thread = threading.Thread(target=schedule_checker, daemon=True)
    scheduler_thread.start()

# Error handlers
@app.errorhandler(413)
def too_large(e):
    return jsonify({'error': 'File too large. Maximum size is 16MB'}), 413

@app.errorhandler(404)
def not_found(e):
    # Check if it's an API request
    if request.path.startswith('/api/'):
        return jsonify({'error': 'API endpoint not found'}), 404
    else:
        return jsonify({'error': 'Page not found'}), 404

@app.errorhandler(500)
def internal_error(e):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    # Ensure required directories exist
    os.makedirs("logs", exist_ok=True)
    os.makedirs("reports", exist_ok=True)
    os.makedirs("uploads", exist_ok=True)
    os.makedirs("templates", exist_ok=True)
    
    # Check PDF capabilities on startup
    print("Checking PDF generation capabilities...")
    pdf_status = check_pdf_dependencies()
    print(f"PDF Status: {pdf_status['message']}")
    
    # Start background scheduler
    start_scheduler()
    
    print("CIS Auditor Web API Starting...")
    print("API Endpoints:")
    print("  POST /api/audit/run - Run single target audit")
    print("  POST /api/audit/batch - Run batch audit from file")
    print("  GET  /api/audits/active - List all audits")
    print("  GET  /api/audit/<id>/status - Get audit status")
    print("  GET  /api/audit/<id>/report - Download HTML report")
    print("  GET  /api/audit/<id>/report?format=pdf - Download PDF report")
    print("  POST /api/schedule - Schedule audit")
    print("  GET  /api/schedule - List scheduled audits")
    print("  DELETE /api/schedule/<id> - Delete scheduled audit")
    print("  GET  /api/health - Health check")
    print("  GET  /api/pdf-status - Check PDF capabilities")
    print("  POST /api/install-pdf - Install PDF dependencies")
    print("  POST /api/upload-test - Test file upload")
    print("")
    print("Web UI available at: http://localhost:5000")
    print("Use Ctrl+C to stop the server")
    
    app.run(debug=True, host='0.0.0.0', port=5000, threaded=True)
