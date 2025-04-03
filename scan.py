from flask import Flask, request, jsonify
import os
import yara
import json
import logging
from werkzeug.utils import secure_filename
import sys
import uuid
import subprocess

app = Flask(__name__)

# Configure logging to file and console
LOG_FILE_PATH = os.getenv("YARA_LOG", "/tmp/yara_startup.log")
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE_PATH),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configurable paths
UPLOAD_FOLDER = os.getenv("YARA_UNPROCESSED", "/tmp/unprocessed/")
REPORT_FOLDER = os.getenv("YARA_REPORTS", "/tmp/reports/")
YARA_SOURCE_PATH = "/app/yara_rules/index.yar"
YARA_COMPILED_PATH = os.getenv("YARA_RULES", "/app/yara_rules/compiled_rules.yarc")

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(REPORT_FOLDER, exist_ok=True)

# Always recompile rules on startup
logger.info("Compiling YARA rules on startup...")
try:
    result = subprocess.run(["yarac", YARA_SOURCE_PATH, YARA_COMPILED_PATH], capture_output=True, text=True)
    if result.returncode != 0:
        logger.error(f"YARA compilation failed: {result.stderr}")
    else:
        logger.info("YARA rules compiled successfully.")
except Exception as e:
    logger.error(f"Failed to invoke yarac: {e}")

# Load compiled rules
try:
    rules = yara.load(YARA_COMPILED_PATH)
    logger.info("Compiled YARA rules loaded successfully.")
except Exception as e:
    logger.error(f"Error loading compiled YARA rules: {e}")
    rules = None

def perform_yara_scan(file_path, filename):
    try:
        matches = rules.match(file_path)
        scan_result = {
            "filename": filename,
            "matches": [match.rule for match in matches]
        }
        result_path = os.path.join(REPORT_FOLDER, f"{filename}.json")
        with open(result_path, "w") as result_file:
            json.dump(scan_result, result_file, indent=4)

        logger.info(f"Scan completed for {filename}. Results saved.")
        return scan_result
    except Exception as e:
        logger.error(f"Error during YARA scan: {e}")
        return {"error": "Scan failed"}

@app.route("/scan", methods=["POST"])
def scan_file():
    if "file" not in request.files:
        logger.warning("Scan request received without a file.")
        return jsonify({"error": "No file provided"}), 400

    file = request.files["file"]
    if file.filename == "":
        logger.warning("Empty filename submitted.")
        return jsonify({"error": "Filename is empty"}), 400

    extension = os.path.splitext(file.filename)[1]
    filename = f"{uuid.uuid4().hex}{extension}"
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    logger.info(f"Received file {filename} for scanning.")

    if rules:
        result = perform_yara_scan(file_path, filename)
        if "error" in result:
            return jsonify(result), 500
        return jsonify(result), 200
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

    try:
        with open(result_path, "r") as result_file:
            data = json.load(result_file)
        logger.info(f"Returning scan results for {filename}.")
        return jsonify(data), 200
    except Exception as e:
        logger.error(f"Error reading result file: {e}")
        return jsonify({"error": "Failed to read scan result"}), 500

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "ci":
        logger.info("Running in CI/CD mode...")
        test_file = "/app/test_samples/test_file.txt"
        if os.path.exists(test_file):
            logger.info("Test file found. Running scan.")
            with open(test_file, "rb") as f:
                filename = f"test_{uuid.uuid4().hex}.txt"
                file_path = os.path.join(UPLOAD_FOLDER, filename)
                with open(file_path, "wb") as dest:
                    dest.write(f.read())

            if rules:
                result = perform_yara_scan(file_path, filename)
                logger.info(f"CI/CD scan result: {json.dumps(result)}")
        else:
            logger.warning("Test file not found for CI/CD mode.")
        sys.exit(0)

    logger.info("Starting Flask YARA API...")
    app.run(host="0.0.0.0", port=5000, debug=True)
