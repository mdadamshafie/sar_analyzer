#!/usr/bin/env python3
"""Debug script — parse SAR files from a sosreport and show exactly what data is extracted.
Drop your sosreport .tar.xz into the same folder and run:
    python debug_sar.py  sosreport-*.tar.xz
Or point it at an already-extracted folder:
    python debug_sar.py  /path/to/extracted/sosreport-folder
"""
import sys, os, re, tarfile, tempfile, shutil
from datetime import datetime
from collections import Counter

# ---- Minimal SAR parser (same logic as streamlit_app_v7) ----
TIMESTAMP_PATTERN = r'^(\d{2}:\d{2}:\d{2})\s*(AM|PM)?'
DATE_PATTERN = r'(\d{2}/\d{2}/\d{4}|\d{4}-\d{2}-\d{2})'

def extract_data_columns(header_line, anchor_keyword):
    parts = header_line.split()
    anchor_lower = anchor_keyword.lower()
    for i, p in enumerate(parts):
        if p.lower() == anchor_lower or anchor_lower in p.lower():
            return parts[i:]
    if len(parts) > 2 and parts[1] in ('AM', 'PM'):
        return parts[2:]
    elif len(parts) > 1:
        return parts[1:]
    return parts


def find_sar_files(base_path):
    """Find SAR text files in sosreport"""
    files = []
    # sos_commands/sar/ directory
    sos_sar = os.path.join(base_path, 'sos_commands', 'sar')
    if os.path.isdir(sos_sar):
        for f in os.listdir(sos_sar):
            fp = os.path.join(sos_sar, f)
            if os.path.isfile(fp) and os.path.getsize(fp) > 100:
                files.append(fp)
    # var/log/sa/sar* text files
    sa_dir = os.path.join(base_path, 'var', 'log', 'sa')
    if os.path.isdir(sa_dir):
        for f in os.listdir(sa_dir):
            if re.match(r'^sar\d+', f):
                fp = os.path.join(sa_dir, f)
                if os.path.isfile(fp):
                    files.append(fp)
    return files


def parse_sar_file(filepath):
    """Parse a single SAR text file and return debug info."""
    try:
        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
            lines = f.readlines()
    except:
        return None

    info = {
        'file': os.path.basename(filepath),
        'path': filepath,
        'lines': len(lines),
        'date': None,
        'format': None,  # '12h' or '24h'
        'sections': [],
        'cpu_ids': set(),
        'disk_devices': set(),
        'network_ifaces': set(),
        'cpu_fields': [],
        'disk_fields': [],
        'cpu_count': 0,
        'cpu_all_count': 0,
        'cpu_per_count': 0,
        'disk_count': 0,
        'mem_count': 0,
        'load_count': 0,
        'net_count': 0,
        'sample_cpu_line': None,
        'sample_cpu_header': None,
        'sample_disk_line': None,
        'sample_disk_header': None,
    }

    # Detect date from header
    for line in lines[:5]:
        m = re.search(DATE_PATTERN, line)
        if m:
            info['date'] = m.group(1)
            break

    # Detect 12h vs 24h
    for line in lines:
        m = re.match(TIMESTAMP_PATTERN, line.strip())
        if m:
            if m.group(2):
                info['format'] = '12h (AM/PM)'
            else:
                info['format'] = '24h'
            break

    # Parse sections
    current_section = None
    header_found = False
    data_columns = []

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

        if not line:
            if current_section:
                header_found = False
            continue

        if line.startswith('Average:'):
            header_found = False
            continue

        # CPU section
        if '%user' in line and '%system' in line:
            current_section = 'CPU'
            header_found = True
            data_columns = extract_data_columns(line, 'CPU')
            info['cpu_fields'] = data_columns
            if not info['sample_cpu_header']:
                info['sample_cpu_header'] = line
            if 'CPU' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'CPU', 'line': i+1})
            continue

        # Disk section
        if 'DEV' in line and ('tps' in line or 'rd_sec' in line or 'rkB' in line):
            current_section = 'DISK'
            header_found = True
            data_columns = extract_data_columns(line, 'DEV')
            info['disk_fields'] = data_columns
            if not info['sample_disk_header']:
                info['sample_disk_header'] = line
            if 'DISK' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'DISK', 'line': i+1})
            continue

        # Memory section
        if 'kbmemfree' in line:
            current_section = 'MEMORY'
            header_found = True
            if 'MEMORY' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'MEMORY', 'line': i+1})
            continue

        # Load section
        if 'ldavg-1' in line:
            current_section = 'LOAD'
            header_found = True
            if 'LOAD' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'LOAD', 'line': i+1})
            continue

        # Network section
        if 'IFACE' in line and ('rxpck' in line or 'rxkB' in line):
            current_section = 'NETWORK'
            header_found = True
            if 'NETWORK' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'NETWORK', 'line': i+1})
            continue

        # Swap
        if 'kbswpfree' in line:
            current_section = 'SWAP'
            header_found = True
            if 'SWAP' not in [s['name'] for s in info['sections']]:
                info['sections'].append({'name': 'SWAP', 'line': i+1})
            continue

        # Data lines
        if header_found:
            m = re.match(TIMESTAMP_PATTERN, line)
            if m:
                parts = line.split()
                am_pm = parts[1] if len(parts) > 1 and parts[1] in ['AM', 'PM'] else None
                offset = 2 if am_pm else 1

                if current_section == 'CPU' and len(parts) > offset:
                    cpu_id = parts[offset]
                    info['cpu_ids'].add(cpu_id)
                    info['cpu_count'] += 1
                    if cpu_id == 'all':
                        info['cpu_all_count'] += 1
                    else:
                        info['cpu_per_count'] += 1
                    if not info['sample_cpu_line']:
                        info['sample_cpu_line'] = line

                elif current_section == 'DISK' and len(parts) > offset:
                    device = parts[offset]
                    info['disk_devices'].add(device)
                    info['disk_count'] += 1
                    if not info['sample_disk_line']:
                        info['sample_disk_line'] = line

                elif current_section == 'NETWORK' and len(parts) > offset:
                    iface = parts[offset]
                    info['network_ifaces'].add(iface)
                    info['net_count'] += 1

                elif current_section == 'MEMORY':
                    info['mem_count'] += 1

                elif current_section == 'LOAD':
                    info['load_count'] += 1

    return info


def main():
    if len(sys.argv) < 2:
        # Auto-find .tar.xz in current dir
        candidates = [f for f in os.listdir('.') if f.endswith(('.tar.xz', '.tar.gz', '.tar.bz2')) and 'sosreport' in f.lower()]
        if not candidates:
            # Try extracted folders
            candidates = [f for f in os.listdir('.') if os.path.isdir(f) and 'sosreport' in f.lower()]
        if candidates:
            target = candidates[0]
            print(f"Auto-found: {target}")
        else:
            print("Usage: python debug_sar.py <sosreport.tar.xz | sosreport-folder>")
            sys.exit(1)
    else:
        target = sys.argv[1]

    # Extract if tar
    cleanup = False
    if os.path.isfile(target) and ('.tar' in target):
        print(f"Extracting {target}...")
        tmpdir = tempfile.mkdtemp(prefix='sar_debug_')
        try:
            with tarfile.open(target) as tf:
                tf.extractall(tmpdir)
        except Exception as e:
            print(f"Extraction failed: {e}")
            sys.exit(1)
        # Find the sosreport root inside
        subdirs = [d for d in os.listdir(tmpdir) if os.path.isdir(os.path.join(tmpdir, d))]
        if subdirs:
            base_path = os.path.join(tmpdir, subdirs[0])
        else:
            base_path = tmpdir
        cleanup = True
        print(f"Extracted to: {base_path}")
    else:
        base_path = target

    if not os.path.isdir(base_path):
        print(f"Not a directory: {base_path}")
        sys.exit(1)

    # Find SAR files
    sar_files = find_sar_files(base_path)
    print(f"\n{'='*70}")
    print(f"Found {len(sar_files)} SAR files")
    print(f"{'='*70}")

    if not sar_files:
        # Show what's in expected dirs
        for d in ['sos_commands/sar', 'var/log/sa']:
            dp = os.path.join(base_path, d)
            if os.path.isdir(dp):
                print(f"\n  {d}/: {os.listdir(dp)}")
            else:
                print(f"\n  {d}/ does NOT exist")
        print("\nNo SAR files found!")
    else:
        for filepath in sorted(sar_files):
            info = parse_sar_file(filepath)
            if not info:
                print(f"\n  {os.path.basename(filepath)}: FAILED TO READ")
                continue

            print(f"\n{'─'*70}")
            print(f"  File:     {info['file']}")
            print(f"  Path:     {info['path']}")
            print(f"  Lines:    {info['lines']}")
            print(f"  Date:     {info['date']}")
            print(f"  Format:   {info['format']}")
            section_strs = [s['name'] + ' (L' + str(s['line']) + ')' for s in info['sections']]
            print(f"  Sections: {', '.join(section_strs)}")
            print()
            print(f"  CPU data rows:  {info['cpu_count']} total ({info['cpu_all_count']} 'all', {info['cpu_per_count']} per-CPU)")
            print(f"  CPU IDs found:  {sorted(info['cpu_ids'], key=lambda x: (x!='all', int(x) if x.isdigit() else 999))}")
            print(f"  CPU columns:    {info['cpu_fields']}")
            if info['sample_cpu_header']:
                print(f"  CPU header:     {info['sample_cpu_header'][:120]}")
            if info['sample_cpu_line']:
                print(f"  CPU sample:     {info['sample_cpu_line'][:120]}")
            print()
            print(f"  Disk data rows: {info['disk_count']}")
            print(f"  Disk devices:   {sorted(info['disk_devices'])}")
            print(f"  Disk columns:   {info['disk_fields']}")
            if info['sample_disk_header']:
                print(f"  Disk header:    {info['sample_disk_header'][:120]}")
            if info['sample_disk_line']:
                print(f"  Disk sample:    {info['sample_disk_line'][:120]}")
            print()
            print(f"  Memory rows:    {info['mem_count']}")
            print(f"  Load rows:      {info['load_count']}")
            print(f"  Network rows:   {info['net_count']}  (interfaces: {sorted(info['network_ifaces'])})")

    # Also check what will happen with field names after InfluxDB push transform
    print(f"\n{'='*70}")
    print("INFLUXDB FIELD NAME TRANSFORM (what the push function produces):")
    print(f"{'='*70}")
    if sar_files:
        info = parse_sar_file(sorted(sar_files)[0])
        if info:
            print("\n  CPU fields → InfluxDB:")
            for col in info['cpu_fields']:
                transformed = col.replace(' ', '_').replace('/', '_').replace('%', 'pct_')
                print(f"    {col:15s} → {transformed}")
            print("\n  Disk fields → InfluxDB:")
            for col in info['disk_fields']:
                transformed = col.replace(' ', '_').replace('/', '_').replace('%', 'pct_')
                print(f"    {col:15s} → {transformed}")

    # Check /proc/uptime for dmesg timestamp derivation
    proc_uptime = os.path.join(base_path, 'proc', 'uptime')
    if os.path.isfile(proc_uptime):
        with open(proc_uptime, 'r') as f:
            print(f"\n  /proc/uptime: {f.read().strip()}")
    else:
        print(f"\n  /proc/uptime: NOT FOUND")

    # Check dmesg
    dmesg_files = []
    for d in ['sos_commands/kernel', 'var/log']:
        dp = os.path.join(base_path, d)
        if os.path.isdir(dp):
            for f in os.listdir(dp):
                if 'dmesg' in f.lower():
                    fp = os.path.join(dp, f)
                    if os.path.isfile(fp):
                        dmesg_files.append(fp)
    if dmesg_files:
        print(f"\n  dmesg files found: {len(dmesg_files)}")
        for df in dmesg_files:
            with open(df, 'r', errors='ignore') as f:
                first_line = f.readline().strip()
            print(f"    {os.path.basename(df)}: {first_line[:100]}")

    if cleanup:
        shutil.rmtree(tmpdir, ignore_errors=True)

    print(f"\n{'='*70}")
    print("DONE")


if __name__ == '__main__':
    main()
