from flask import Flask, request, jsonify
import os
import yara
import json
import logging
from werkzeug.utils import secure_filename
import sys

app = Flask(__name__)

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Configurable directories
UPLOAD_FOLDER = os.getenv("YARA_UNPROCESSED", "/tmp/unprocessed/")
REPORT_FOLDER = os.getenv("YARA_REPORTS", "/tmp/reports/")
YARA_RULES_PATH = os.getenv("YARA_RULES", "/app/yara_rules/yara_index.yar")


# Ensure necessary directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Load YARA rules
try:
    rules = yara.compile(YARA_RULES_PATH)
    logger.info("YARA rules loaded successfully.")
except Exception as e:
    logger.error(f"Error loading YARA rules: {e}")
    rules = None

@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        logger.warning("Scan request received without a file.")
        return jsonify({"error": "No file provided"}), 400
    
    file = request.files["file"]
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    logger.info(f"Received file {filename} for scanning.")
    
    if rules:
        matches = rules.match(file_path)
        scan_result = {"filename": filename, "matches": [match.rule for match in matches]} 
        result_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
        
        with open(result_path, "w") as result_file:
            json.dump(scan_result, result_file, indent=4)
        
        logger.info(f"Scan completed for {filename}. Results saved.")
        
        return jsonify(scan_result), 200
    else:
        logger.error("YARA rules not loaded, cannot perform scan.")
        return jsonify({"error": "YARA rules not loaded"}), 500

@app.route("/results", methods=["GET"])
def get_results():
    filename = request.args.get("filename")
    if not filename:
        logger.warning("Results request received without specifying a filename.")
        return jsonify({"error": "Filename required"}), 400
    
    result_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
    if not os.path.exists(result_path):
        logger.info(f"No results found for {filename}.")
        return jsonify({"error": "No results found for specified file"}), 404
    
    with open(result_path, "r") as result_file:
        data = json.load(result_file)
    
    logger.info(f"Returning scan results for {filename}.")
    return jsonify(data), 200

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "ci":
        logger.info("Running in CI/CD mode...")
        test_file = "/app/test_samples/test_file.txt"
        if os.path.exists(test_file):
            with open(test_file, "rb") as f:
                test_response = scan_file()
            logger.info(f"CI/CD scan response: {test_response.get_json()}")
        sys.exit(0)
    
    logger.info("Starting Flask YARA API...")
    app.run(host="0.0.0.0", port=5000, debug=True)