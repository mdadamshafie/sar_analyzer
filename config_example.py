"""
Example configuration for SOSreport SAR Analyzer
Copy this file to config.py and update with your settings
"""

# InfluxDB Configuration
INFLUXDB_CONFIG = {
    "url": "http://localhost:8086",
    "token": "your-influxdb-api-token-here",
    "org": "your-organization",
    "bucket": "sar_metrics"
}

# Default hostname if not provided
DEFAULT_HOSTNAME = "unknown"

# Batch size for pushing metrics to InfluxDB
BATCH_SIZE = 1000

# SAR file search patterns within SOSreport
SAR_PATHS = [
    "sos_commands/sar/*",
    "var/log/sa/*",
    "sar/*"
]
