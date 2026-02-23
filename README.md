# SOSreport SAR Data Analyzer

A Python tool to parse SAR (System Activity Report) data from SOSreport files and push metrics to InfluxDB for visualization in Grafana.

## Features

- **Parse SAR data** from SOSreport directories
- **Extract multiple metric types**:
  - CPU utilization (`%user`, `%system`, `%iowait`, etc.)
  - Memory usage (`kbmemfree`, `kbmemused`, `%memused`, etc.)
  - Disk I/O (`tps`, `rd_sec/s`, `wr_sec/s`, etc.)
  - Network traffic (`rxpck/s`, `txpck/s`, `rxkB/s`, `txkB/s`, etc.)
  - System load (`ldavg-1`, `ldavg-5`, `ldavg-15`, etc.)
- **Push metrics to InfluxDB** (time-series database)
- **Generate Grafana dashboards** automatically

## Prerequisites

1. **Python 3.8+**
2. **InfluxDB 2.x** running and accessible
3. **Grafana** (optional, for visualization)

## Installation

```bash
# Clone or download the script
cd sar_analyzer

# Install dependencies
pip install -r requirements.txt
```

## InfluxDB Setup

1. Start InfluxDB and create an organization and bucket:
   ```bash
   # Create bucket via InfluxDB UI or CLI
   influx bucket create --name sar_metrics --org your-org
   ```

2. Generate an API token with write access to the bucket

## Usage

### Basic Usage

```bash
python sar_analyzer.py /path/to/sosreport \
    --hostname server01 \
    --influx-token YOUR_INFLUXDB_TOKEN \
    --influx-org your-organization
```

### All Options

```bash
python sar_analyzer.py /path/to/sosreport \
    --hostname server01 \
    --influx-url http://localhost:8086 \
    --influx-token YOUR_INFLUXDB_TOKEN \
    --influx-org your-organization \
    --influx-bucket sar_metrics \
    --generate-dashboard
```

### Command Line Arguments

| Argument | Description | Default |
|----------|-------------|---------|
| `sosreport_path` | Path to extracted SOSreport directory | (required) |
| `--hostname` | Hostname for tagging metrics | `unknown` |
| `--influx-url` | InfluxDB server URL | `http://localhost:8086` |
| `--influx-token` | InfluxDB API token | (required) |
| `--influx-org` | InfluxDB organization | (required) |
| `--influx-bucket` | InfluxDB bucket name | `sar_metrics` |
| `--generate-dashboard` | Generate Grafana dashboard JSON | `False` |
| `--dry-run` | Parse data without pushing to InfluxDB | `False` |

### Dry Run Mode

Test the parser without sending data to InfluxDB:

```bash
python sar_analyzer.py /path/to/sosreport --dry-run
```

## SOSreport SAR File Locations

The tool searches for SAR data in these locations within the SOSreport:

- `sos_commands/sar/*`
- `var/log/sa/*`
- `sar/*`

## Grafana Dashboard

When using `--generate-dashboard`, a JSON file will be created that can be imported into Grafana:

1. Open Grafana → Dashboards → Import
2. Upload the generated `grafana_dashboard_<hostname>.json`
3. Configure InfluxDB data source if not already done

## Example Output

```
============================================================
SOSreport SAR Data Analyzer
============================================================

Found 3 SAR files
Parsing: /path/sosreport/sos_commands/sar/sar
  Extracted 1542 metrics
Parsing: /path/sosreport/sos_commands/sar/sar_-r
  Extracted 288 metrics
Parsing: /path/sosreport/sos_commands/sar/sar_-b
  Extracted 144 metrics

Total metrics extracted: 1974

Metrics by type:
  cpu: 1152
  disk: 288
  load: 144
  memory: 288
  network: 102

============================================================
Pushing to InfluxDB
============================================================

Connected to InfluxDB at http://localhost:8086
Pushing 1974 metrics to InfluxDB...
  Progress: 1000/1974 (50%)
  Progress: 1974/1974 (100%)
Successfully pushed 1974 metrics to InfluxDB
Disconnected from InfluxDB

============================================================
Done!
============================================================
```

## InfluxDB Data Structure

Metrics are stored with the following structure:

- **Measurement**: `sar_<type>` (e.g., `sar_cpu`, `sar_memory`)
- **Tags**:
  - `host`: Server hostname
  - `cpu`: CPU ID (for CPU metrics)
  - `device`: Device name (for disk metrics)
  - `interface`: Network interface (for network metrics)
- **Fields**: The actual metric values
- **Timestamp**: Original SAR timestamp

## Grafana Queries

Example InfluxDB Flux queries for Grafana:

### CPU Usage
```flux
from(bucket: "sar_metrics")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "sar_cpu")
  |> filter(fn: (r) => r.cpu == "all")
  |> filter(fn: (r) => r._field == "pct_user" or r._field == "pct_system")
```

### Memory Usage
```flux
from(bucket: "sar_metrics")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "sar_memory")
  |> filter(fn: (r) => r._field == "pct_memused")
```

### Load Average
```flux
from(bucket: "sar_metrics")
  |> range(start: v.timeRangeStart, stop: v.timeRangeStop)
  |> filter(fn: (r) => r._measurement == "sar_load")
  |> filter(fn: (r) => r._field =~ /ldavg_/)
```

## Troubleshooting

### No SAR files found
- Ensure the SOSreport is extracted
- Check the directory structure matches expected paths

### Connection refused to InfluxDB
- Verify InfluxDB is running: `influx ping`
- Check the URL and port

### Authentication errors
- Verify the API token has write permissions
- Check the organization name

## License

MIT License
