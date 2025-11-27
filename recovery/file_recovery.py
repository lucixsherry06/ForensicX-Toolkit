# forensic_tool/recovery/file_recovery.py
import os
import time
import logging
import subprocess
import signal
import struct
import binascii
from datetime import timedelta, datetime
from pathlib import Path
from typing import List, Optional

# --- keep your signatures, patterns and constants ---
FILE_SIGNATURES = {
    'jpg': [bytes([0xFF, 0xD8, 0xFF, 0xE0]), bytes([0xFF, 0xD8, 0xFF, 0xE1])],
    'png': [bytes([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A])],
    'gif': [bytes([0x47, 0x49, 0x46, 0x38, 0x37, 0x61]), bytes([0x47, 0x49, 0x46, 0x38, 0x39, 0x61])],
    'pdf': [bytes([0x25, 0x50, 0x44, 0x46])],
    'zip': [bytes([0x50, 0x4B, 0x03, 0x04])],
    'docx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'xlsx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'pptx': [bytes([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x06, 0x00])],
    'mp3': [bytes([0x49, 0x44, 0x33])],
    'mp4': [bytes([0x00, 0x00, 0x00, 0x18, 0x66, 0x74, 0x79, 0x70])],
    'avi': [bytes([0x52, 0x49, 0x46, 0x46])],
}

VALIDATION_PATTERNS = {
    'docx': [b'word/', b'[Content_Types].xml'],
    'xlsx': [b'xl/', b'[Content_Types].xml'],
    'pptx': [b'ppt/', b'[Content_Types].xml'],
    'zip': [b'PK\x01\x02'],
    'pdf': [b'obj', b'endobj'],
}

FILE_TRAILERS = {
    'jpg': bytes([0xFF, 0xD9]),
    'png': bytes([0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
    'gif': bytes([0x00, 0x3B]),
    'pdf': bytes([0x25, 0x25, 0x45, 0x4F, 0x46]),
}

MAX_FILE_SIZES = {
    'jpg': 30 * 1024 * 1024,
    'png': 50 * 1024 * 1024,
    'gif': 20 * 1024 * 1024,
    'pdf': 100 * 1024 * 1024,
    'zip': 200 * 1024 * 1024,
    'docx': 50 * 1024 * 1024,
    'xlsx': 50 * 1024 * 1024,
    'pptx': 100 * 1024 * 1024,
    'mp3': 50 * 1024 * 1024,
    'mp4': 1024 * 1024 * 1024,
    'avi': 1024 * 1024 * 1024,
}


class FileRecoveryTool:
    def __init__(
        self,
        source: str,
        output_dir: str,
        file_types: Optional[List[str]] = None,
        deep_scan: bool = False,
        block_size: int = 512,
        log_level: int = logging.INFO,
        skip_existing: bool = True,
        max_scan_size: Optional[int] = None,
        timeout_minutes: Optional[int] = None,
    ):
        self.source = source
        self.output_dir = Path(output_dir)
        self.file_types = file_types if file_types else list(FILE_SIGNATURES.keys())
        self.deep_scan = deep_scan
        self.block_size = block_size
        self.skip_existing = skip_existing
        self.max_scan_size = max_scan_size
        self.timeout_minutes = timeout_minutes
        self.timeout_reached = False

        self.setup_logging(log_level)
        self.output_dir.mkdir(parents=True, exist_ok=True)

        self.stats = {
            'total_files_recovered': 0,
            'recovered_by_type': {},
            'start_time': time.time(),
            'bytes_scanned': 0,
            'false_positives': 0
        }
        for f in self.file_types:
            self.stats['recovered_by_type'][f] = 0

    def setup_logging(self, log_level):
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(f"recovery_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
            ]
        )
        self.logger = logging.getLogger('file_recovery')

    def _setup_timeout(self):
        if self.timeout_minutes:
            def timeout_handler(signum, frame):
                self.logger.warning(f"Timeout of {self.timeout_minutes} minutes reached!")
                self.timeout_reached = True
            signal.signal(signal.SIGALRM, timeout_handler)
            signal.alarm(int(self.timeout_minutes * 60))

    def get_device_size(self):
        if os.path.isfile(self.source):
            return os.path.getsize(self.source)
        else:
            # try blockdev
            try:
                result = subprocess.run(['blockdev', '--getsize64', self.source],
                                        capture_output=True, text=True, check=True)
                return int(result.stdout.strip())
            except (subprocess.SubprocessError, FileNotFoundError):
                try:
                    import fcntl
                    with open(self.source, 'rb') as fd:
                        buf = bytearray(8)
                        fcntl.ioctl(fd, 0x80081272, buf)
                        return struct.unpack('L', buf)[0]
                except Exception:
                    try:
                        with open(self.source, 'rb') as fd:
                            fd.seek(0, 2)
                            return fd.tell()
                    except Exception:
                        self.logger.warning("Could not determine device size. Using fallback 1GB.")
                        return 1024 * 1024 * 1024

    def scan_device(self) -> bool:
        self.logger.info(f"Starting scan of {self.source}")
        self.logger.info(f"Looking for file types: {', '.join(self.file_types)}")
        try:
            device_size = self.get_device_size()
            self.logger.info(f"Device size: {self._format_size(device_size)}")

            if self.timeout_minutes:
                self._setup_timeout()
                self.logger.info(f"Timeout set for {self.timeout_minutes} minutes")

            with open(self.source, 'rb', buffering=0) as device:
                self._scan_device_data(device, device_size)
        except (IOError, OSError) as e:
            self.logger.error(f"Error accessing source: {e}")
            return False

        self._print_summary()
        return True

    def _scan_device_data(self, device, device_size):
        position = 0
        if self.max_scan_size and self.max_scan_size < device_size:
            self.logger.info(f"Limiting scan to first {self._format_size(self.max_scan_size)}")
            device_size = self.max_scan_size

        for file_type in self.file_types:
            (self.output_dir / file_type).mkdir(exist_ok=True)

        scan_start_time = time.time()
        last_progress_time = scan_start_time

        while position < device_size:
            if self.timeout_reached:
                self.logger.warning("Stopping scan due to timeout")
                break
            try:
                device.seek(position)
                data = device.read(self.block_size)
                if not data:
                    break
                self.stats['bytes_scanned'] += len(data)

                for file_type in self.file_types:
                    signatures = FILE_SIGNATURES.get(file_type, [])
                    for signature in signatures:
                        sig_pos = data.find(signature)
                        if sig_pos != -1:
                            absolute_pos = position + sig_pos
                            device.seek(absolute_pos)
                            self.logger.debug(f"Found {file_type} signature at position {absolute_pos}")
                            if self._recover_file(device, file_type, absolute_pos):
                                self.stats['total_files_recovered'] += 1
                                self.stats['recovered_by_type'][file_type] += 1
                            else:
                                self.stats['false_positives'] += 1
                            device.seek(position + self.block_size)

                position += self.block_size
                current_time = time.time()
                if (position % (5 * 1024 * 1024) == 0) or (current_time - last_progress_time >= 10):
                    percent = (position / device_size) * 100 if device_size > 0 else 0
                    elapsed = current_time - self.stats['start_time']
                    if position > 0 and device_size > 0:
                        bytes_per_second = position / elapsed if elapsed > 0 else 0
                        remaining_bytes = device_size - position
                        eta_seconds = remaining_bytes / bytes_per_second if bytes_per_second > 0 else 0
                        eta_str = str(timedelta(seconds=int(eta_seconds)))
                    else:
                        eta_str = "unknown"
                    self.logger.info(
                        f"Progress: {percent:.2f}% ({self._format_size(position)} / {self._format_size(device_size)}) - "
                        f"{self.stats['total_files_recovered']} files recovered - "
                        f"Elapsed: {timedelta(seconds=int(elapsed))} - ETA: {eta_str}"
                    )
                    last_progress_time = current_time
            except Exception as e:
                self.logger.error(f"Error reading at position {position}: {e}")
                position += self.block_size

    def _validate_file_content(self, data: bytes, file_type: str) -> bool:
        if len(data) < 100:
            return False
        patterns = VALIDATION_PATTERNS.get(file_type, [])
        if patterns:
            for pattern in patterns:
                if pattern in data:
                    return True
            return False
        return True

    def _recover_file(self, device, file_type: str, start_position: int) -> bool:
        max_size = MAX_FILE_SIZES.get(file_type, 10 * 1024 * 1024)
        trailer = FILE_TRAILERS.get(file_type)
        filename = f"{file_type}_{start_position}_{int(time.time())}_{binascii.hexlify(os.urandom(4)).decode()}.{file_type}"
        output_path = self.output_dir / file_type / filename

        if self.skip_existing and output_path.exists():
            self.logger.debug(f"Skipping existing file: {output_path}")
            return False

        current_pos = device.tell()
        try:
            device.seek(start_position)
            if trailer and self.deep_scan:
                file_data = self._read_until_trailer(device, trailer, max_size)
            else:
                file_data = self._read_file_heuristic(device, file_type, max_size)

            if not file_data or len(file_data) < 100:
                return False

            if not self._validate_file_content(file_data, file_type):
                self.logger.debug(f"Skipping invalid {file_type} file at position {start_position}")
                return False

            with open(output_path, 'wb') as f:
                f.write(file_data)

            self.logger.info(f"Recovered {file_type} file: {filename} ({self._format_size(len(file_data))})")
            return True
        except Exception as e:
            self.logger.error(f"Error recovering file at position {start_position}: {e}")
            return False
        finally:
            try:
                device.seek(current_pos)
            except Exception:
                pass

    def _read_until_trailer(self, device, trailer: bytes, max_size: int):
        buffer = bytearray()
        chunk_size = 4096
        while len(buffer) < max_size:
            try:
                chunk = device.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                trailer_pos = buffer.find(trailer, max(0, len(buffer) - len(trailer) - chunk_size))
                if trailer_pos != -1:
                    return buffer[:trailer_pos + len(trailer)]
            except Exception as e:
                self.logger.error(f"Error reading chunk: {e}")
                break
        return buffer if len(buffer) > 100 else None

    def _read_file_heuristic(self, device, file_type: str, max_size: int):
        buffer = bytearray()
        chunk_size = 4096
        valid_chunks = 0
        invalid_chunks = 0
        initial_chunk_size = 16384 if file_type in ['docx', 'xlsx', 'pptx', 'zip'] else chunk_size
        initial_chunk = device.read(initial_chunk_size)
        if not initial_chunk:
            return None
        buffer.extend(initial_chunk)
        if file_type in ['docx', 'xlsx', 'pptx', 'zip']:
            if file_type == 'docx' and b'word/' not in initial_chunk:
                return None
            if file_type == 'xlsx' and b'xl/' not in initial_chunk:
                return None
            if file_type == 'pptx' and b'ppt/' not in initial_chunk:
                return None
            if file_type == 'zip' and b'PK\x01\x02' not in initial_chunk:
                return None
        while len(buffer) < max_size:
            try:
                chunk = device.read(chunk_size)
                if not chunk:
                    break
                buffer.extend(chunk)
                if file_type in ['jpg', 'png', 'gif', 'pdf', 'zip', 'docx', 'xlsx', 'pptx', 'mp3', 'mp4', 'avi']:
                    valid_chunks += 1
                    if file_type in ['zip', 'docx', 'xlsx', 'pptx'] and b'PK' not in chunk and valid_chunks > 10:
                        invalid_chunks += 1
                else:
                    printable_ratio = sum(32 <= b <= 126 or b in (9, 10, 13) for b in chunk) / len(chunk)
                    if printable_ratio < 0.7:
                        invalid_chunks += 1
                    else:
                        valid_chunks += 1
                if invalid_chunks > 3:
                    return buffer[:len(buffer) - (invalid_chunks * chunk_size)]
            except Exception as e:
                self.logger.error(f"Error reading chunk in heuristic: {e}")
                break
        return buffer

    def _format_size(self, size_bytes: int) -> str:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024 or unit == 'TB':
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024

    def _print_summary(self):
        elapsed = time.time() - self.stats['start_time']
        self.logger.info("=" * 50)
        self.logger.info("Recovery Summary")
        self.logger.info("=" * 50)
        self.logger.info(f"Total files recovered: {self.stats['total_files_recovered']}")
        self.logger.info(f"False positives detected and skipped: {self.stats['false_positives']}")
        self.logger.info(f"Total data scanned: {self._format_size(self.stats['bytes_scanned'])}")
        self.logger.info(f"Time elapsed: {timedelta(seconds=int(elapsed))}")
        self.logger.info("Files recovered by type:")
        for file_type, count in self.stats['recovered_by_type'].items():
            if count > 0:
                self.logger.info(f"  - {file_type}: {count}")
        if self.timeout_reached:
            self.logger.info("Note: Scan was stopped due to timeout")
        self.logger.info("=" * 50)


# --- wrapper to be called from the CLI ---
def recover_files(
    source: str,
    output: str,
    types: Optional[List[str]] = None,
    deep_scan: bool = False,
    block_size: int = 512,
    verbose: bool = False,
    quiet: bool = False,
    no_skip: bool = False,
    max_size_mb: Optional[int] = None,
    timeout_minutes: Optional[int] = None,
) -> bool:
    """
    Wrapper for the CLI. Returns True on success False on failure.
    """
    log_level = logging.ERROR if quiet else (logging.DEBUG if verbose else logging.INFO)
    max_bytes = max_size_mb * 1024 * 1024 if max_size_mb else None

    tool = FileRecoveryTool(
        source=source,
        output_dir=output,
        file_types=types,
        deep_scan=deep_scan,
        block_size=block_size,
        log_level=log_level,
        skip_existing=not no_skip,
        max_scan_size=max_bytes,
        timeout_minutes=timeout_minutes,
    )

    try:
        return tool.scan_device()
    except KeyboardInterrupt:
        print("\n[!] Recovery process interrupted by user.")
        tool._print_summary()
        return False
