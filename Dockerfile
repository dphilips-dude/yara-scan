# Use a lightweight Alpine base image
FROM alpine:latest

# Set working directory
WORKDIR /app

# Install dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    yara \
    git
# Create virtual environment
RUN python3 -m venv /venv && \
    . /venv/bin/activate && \
    pip install --no-cache-dir flask yara-python requests

# Add virtualenv binaries to PATH
ENV PATH="/venv/bin:$PATH"

# Copy the optimized scripts and YARA rules
COPY scan.py /app/yara_scan.py
COPY ReportNormalizer.py /app/report_normalizer.py
COPY yara_rules/ /app/yara_rules/

# Set environment variables for directories
ENV YARA_UNPROCESSED="/tmp/unprocessed/"
ENV YARA_REPORTS="/tmp/reports/"
ENV YARA_PROCESSED="/tmp/processed/"
ENV YARA_ERRORS="/tmp/errorFiles/"
ENV YARA_LOG="/root/log.txt"
ENV YARA_RULES="/app/yara_rules/yara_index.yar"

# Ensure required directories exist
RUN mkdir -p $YARA_UNPROCESSED $YARA_REPORTS $YARA_PROCESSED $YARA_ERRORS

# Run the optimized YARA scanner automatically on startup
ENTRYPOINT ["python3", "/app/yara_scan.py"]
