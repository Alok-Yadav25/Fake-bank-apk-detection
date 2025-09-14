from flask import Flask, request, jsonify, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import os
import json
from datetime import datetime
import sqlite3
import hashlib
import traceback
import logging
from apk_analyzer import APKAnalyzer
from ml_detector import MLDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='../frontend/templates', static_folder='../frontend/static')
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = '../frontend/static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB

# Create necessary directories
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('../frontend/static/images', exist_ok=True)

# Initialize analyzers with error handling
try:
    apk_analyzer = APKAnalyzer()
    ml_detector = MLDetector()
    logger.info("Analyzers initialized successfully")
except Exception as e:
    logger.error(f"Error initializing analyzers: {str(e)}")
    apk_analyzer = None
    ml_detector = None

def init_db():
    """Initialize the database with proper error handling."""
    try:
        conn = sqlite3.connect('apk_analysis.db')
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                file_hash TEXT UNIQUE,
                scan_date DATETIME,
                is_malicious BOOLEAN,
                confidence_score REAL,
                analysis_results TEXT,
                permissions TEXT,
                suspicious_features TEXT
            )
        ''')
        conn.commit()
        conn.close()
        logger.info("Database initialized successfully")
    except Exception as e:
        logger.error(f"Database initialization failed: {str(e)}")

# Initialize database
init_db()

def allowed_file(filename):
    """Check if uploaded file is an APK file."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() == 'apk'

def calculate_file_hash(filepath):
    """Calculate SHA256 hash of a file."""
    try:
        sha256_hash = hashlib.sha256()
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception as e:
        logger.error(f"Error calculating file hash: {str(e)}")
        raise

@app.route('/')
def index():
    """Home page route."""
    return render_template('index.html')

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Handle file upload and analysis."""
    if request.method == 'POST':
        try:
            # Check if file is present
            if 'file' not in request.files:
                flash('No file selected', 'error')
                return redirect(request.url)
            
            file = request.files['file']
            if file.filename == '':
                flash('No file selected', 'error')
                return redirect(request.url)
            
            # Validate file type
            if not allowed_file(file.filename):
                flash('Invalid file format. Please upload an APK file.', 'error')
                return redirect(request.url)
            
            # Check if analyzers are available
            if not apk_analyzer or not ml_detector:
                flash('Analysis service temporarily unavailable. Please try again later.', 'error')
                return redirect(request.url)
            
            # Save file with timestamp
            filename = secure_filename(file.filename)
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            
            file.save(filepath)
            logger.info(f"File saved: {filepath}")
            
            # Calculate file hash
            file_hash = calculate_file_hash(filepath)
            
            # Check if file already analyzed
            conn = sqlite3.connect('apk_analysis.db')
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM scan_results WHERE file_hash = ?', (file_hash,))
            existing_result = cursor.fetchone()
            conn.close()
            
            if existing_result:
                os.remove(filepath)  # Remove duplicate file
                flash('File already analyzed. Showing previous results.', 'info')
                return redirect(url_for('results', scan_id=existing_result[0]))
            
            # Analyze APK
            try:
                analysis_result = analyze_apk(filepath, filename, file_hash)
                flash('APK analysis completed successfully!', 'success')
                return redirect(url_for('results', scan_id=analysis_result['scan_id']))
            except Exception as e:
                logger.error(f'APK analysis error: {str(e)}')
                logger.error(traceback.format_exc())
                if os.path.exists(filepath):
                    os.remove(filepath)
                flash(f'Error analyzing APK: {str(e)}', 'error')
                return redirect(request.url)
                
        except Exception as e:
            logger.error(f'Upload error: {str(e)}')
            logger.error(traceback.format_exc())
            flash(f'Upload failed: {str(e)}', 'error')
            return redirect(request.url)
    
    return render_template('upload.html')

def analyze_apk(filepath, filename, file_hash):
    """Analyze APK file and store results."""
    try:
        # Perform static analysis
        static_analysis = apk_analyzer.analyze_apk(filepath)
        if 'error' in static_analysis:
            raise Exception(static_analysis['error'])
        
        # Extract ML features
        features = apk_analyzer.extract_ml_features(static_analysis)
        
        # Get ML prediction
        ml_prediction = ml_detector.predict(features)
        if 'error' in ml_prediction:
            raise Exception(ml_prediction['error'])
        
        # Check banking indicators for enhanced detection
        banking_indicators = static_analysis.get('banking_indicators', {})
        if banking_indicators.get('potential_fake_bank', False):
            ml_prediction['is_malicious'] = True
            ml_prediction['confidence'] = max(ml_prediction['confidence'], 0.8)
        
        # Store results in database
        conn = sqlite3.connect('apk_analysis.db')
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO scan_results
            (filename, file_hash, scan_date, is_malicious, confidence_score,
            analysis_results, permissions, suspicious_features)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            filename,
            file_hash,
            datetime.now(),
            ml_prediction['is_malicious'],
            ml_prediction['confidence'],
            json.dumps(static_analysis),
            json.dumps(static_analysis.get('permissions', {}).get('suspicious_permissions', [])),
            json.dumps(ml_prediction.get('suspicious_features', []))
        ))
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        
        logger.info(f"Analysis completed for {filename}, scan_id: {scan_id}")
        return {'scan_id': scan_id, 'result': ml_prediction}
        
    except Exception as e:
        logger.error(f"APK analysis failed: {str(e)}")
        logger.error(traceback.format_exc())
        raise Exception(f"Analysis failed: {str(e)}")

@app.route('/results/<int:scan_id>')
def results(scan_id):
    """Display scan results."""
    try:
        conn = sqlite3.connect('apk_analysis.db')
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM scan_results WHERE id = ?', (scan_id,))
        result = cursor.fetchone()
        conn.close()
        
        if not result:
            flash('Scan results not found', 'error')
            return redirect(url_for('index'))
        
        scan_data = {
            'id': result[0],
            'filename': result[1],
            'file_hash': result[2],
            'scan_date': result[3],
            'is_malicious': result[4],
            'confidence_score': result[5],
            'analysis_results': json.loads(result[6]) if result[6] else {},
            'permissions': json.loads(result[7]) if result[7] else [],
            'suspicious_features': json.loads(result[8]) if result[8] else []
        }
        
        return render_template('results.html', scan=scan_data)
        
    except Exception as e:
        logger.error(f"Error retrieving results: {str(e)}")
        flash('Error retrieving scan results', 'error')
        return redirect(url_for('index'))

@app.route('/delete_scan/<int:scan_id>', methods=['POST'])
def delete_scan(scan_id):
    """Delete a scan result."""
    try:
        conn = sqlite3.connect('apk_analysis.db')
        cursor = conn.cursor()
        
        # Get the file info before deleting
        cursor.execute('SELECT filename FROM scan_results WHERE id = ?', (scan_id,))
        result = cursor.fetchone()
        
        if result:
            # Delete from database
            cursor.execute('DELETE FROM scan_results WHERE id = ?', (scan_id,))
            conn.commit()
            
            # Try to delete the actual file
            try:
                filename = result[0]
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                if os.path.exists(filepath):
                    os.remove(filepath)
                    logger.info(f"Deleted file: {filepath}")
            except Exception as file_error:
                logger.warning(f"Could not delete file: {file_error}")
            
            flash('Scan result deleted successfully', 'success')
        else:
            flash('Scan result not found', 'error')
            
        conn.close()
        
    except Exception as e:
        logger.error(f'Error deleting scan: {str(e)}')
        flash(f'Error deleting scan: {str(e)}', 'error')
    
    return redirect(url_for('scan_history'))

@app.route('/history')
def scan_history():
    """Display scan history with search functionality."""
    try:
        search_query = request.args.get('search', '')
        
        conn = sqlite3.connect('apk_analysis.db')
        cursor = conn.cursor()
        
        if search_query:
            cursor.execute('''
                SELECT id, filename, scan_date, is_malicious, confidence_score
                FROM scan_results 
                WHERE filename LIKE ? OR file_hash LIKE ?
                ORDER BY scan_date DESC LIMIT 50
            ''', (f'%{search_query}%', f'%{search_query}%'))
        else:
            cursor.execute('''
                SELECT id, filename, scan_date, is_malicious, confidence_score
                FROM scan_results ORDER BY scan_date DESC LIMIT 50
            ''')
        
        results = cursor.fetchall()
        conn.close()
        
        return render_template('history.html', scans=results, search_query=search_query)
        
    except Exception as e:
        logger.error(f"Error retrieving scan history: {str(e)}")
        flash('Error retrieving scan history', 'error')
        return render_template('history.html', scans=[], search_query='')

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error."""
    flash('File too large. Maximum size allowed is 100MB.', 'error')
    return redirect(url_for('upload_file'))

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors."""
    flash('Page not found', 'error')
    return redirect(url_for('index'))

@app.errorhandler(500)
def server_error(e):
    """Handle server errors."""
    logger.error(f"Server error: {str(e)}")
    flash('Internal server error', 'error')
    return redirect(url_for('index'))

# THIS WAS MISSING - MAIN EXECUTION BLOCK
if __name__ == '__main__':
    import sys
    
    # Default configuration
    host = '0.0.0.0'
    port = 8080  # Changed from 5000 to avoid AirPlay conflict
    debug = True
    
    # Parse command line arguments
    if len(sys.argv) > 1:
        for i, arg in enumerate(sys.argv[1:], 1):
            if arg == '--port' and i + 1 < len(sys.argv):
                try:
                    port = int(sys.argv[i + 1])
                except (IndexError, ValueError):
                    logger.warning("Invalid port specified, using default 8080")
            elif arg == '--host' and i + 1 < len(sys.argv):
                host = sys.argv[i + 1]
            elif arg == '--no-debug':
                debug = False
    
    logger.info(f"Starting APK Security Scanner on {host}:{port}")
    
    try:
        app.run(host=host, port=port, debug=debug)
    except Exception as e:
        logger.error(f"Failed to start Flask app: {str(e)}")
        print(f"Error: {str(e)}")
