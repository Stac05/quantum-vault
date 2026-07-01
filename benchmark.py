import sys
import subprocess
import time
import csv
import statistics
import psutil
import hashlib
from pathlib import Path

# Constants
INPUT_DIR = Path("benchmark_data/input")
ENC_DIR = Path("benchmark_data/encrypted")
DEC_DIR = Path("benchmark_data/decrypted")
RESULTS_DIR = Path("results")
RAW_CSV_PATH = RESULTS_DIR / "benchmark_raw.csv"
AVG_CSV_PATH = RESULTS_DIR / "benchmark_average.csv"
MODES = ["whole", "fixed", "adaptive"]
REPETITIONS = 5

def compute_sha256(path):
    sha256 = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()

def setup_directories():
    INPUT_DIR.mkdir(parents=True, exist_ok=True)
    ENC_DIR.mkdir(parents=True, exist_ok=True)
    DEC_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

def generate_keys():
    print("Generating benchmark keys...")
    cmd = [sys.executable, "encrypt.py", "keygen", "--public", "benchmark_pub.pem", "--private", "benchmark_priv.pem"]
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

def run_command_with_metrics(cmd):
    process = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peak_rss = 0
    start_time = time.perf_counter()
    
    try:
        ps_proc = psutil.Process(process.pid)
        while process.poll() is None:
            try:
                mem = ps_proc.memory_info().rss
                if mem > peak_rss:
                    peak_rss = mem
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                break
            time.sleep(0.01)
    except Exception:
        pass
        
    process.communicate()
    elapsed_time = time.perf_counter() - start_time
    
    if process.returncode != 0:
        raise RuntimeError(f"Command failed with return code {process.returncode}")
        
    return elapsed_time, peak_rss

def cleanup_files(enc_output, dec_output):
    if enc_output.exists():
        enc_output.unlink()
    if dec_output.exists():
        dec_output.unlink()
    
    if enc_output.suffix:
        manifest = enc_output.with_suffix(enc_output.suffix + ".manifest.json")
    else:
        manifest = enc_output.with_name(enc_output.name + ".manifest.json")
        
    if manifest.exists():
        manifest.unlink()

def run_benchmark():
    setup_directories()
    
    try:
        generate_keys()
    except subprocess.CalledProcessError:
        print("Error generating keys. Make sure encrypt.py works.")
        sys.exit(1)
        
    files = [f for f in INPUT_DIR.iterdir() if f.is_file()]
    if not files:
        print(f"No files found in {INPUT_DIR}.")
        sys.exit(1)
    
    files.sort(key=lambda x: x.stat().st_size)
    
    # Prepare CSVs
    raw_headers = ["Run", "File Name", "File Size (MB)", "Mode", "Encryption Time", "Decryption Time", "Throughput", "Memory Usage", "Status"]
    with open(RAW_CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(raw_headers)
        
    avg_headers = ["File Name", "File Size (MB)", "Mode", "Average Encryption Time", "Average Decryption Time", "Average Throughput", "Average Memory Usage"]
    
    raw_results = []
    total_runs = len(files) * len(MODES) * REPETITIONS
    current_run = 0
    
    for file_path in files:
        file_size_bytes = file_path.stat().st_size
        file_size_mb = file_size_bytes / (1024 * 1024)
        
        for mode in MODES:
            run_metrics = {
                "enc_times": [],
                "dec_times": [],
                "throughputs": [],
                "memories": []
            }
            
            for run in range(1, REPETITIONS + 1):
                current_run += 1
                print(f"[{current_run}/{total_runs}]")
                print(f"File : {file_path.name}")
                print(f"Mode : {mode.capitalize()}")
                print(f"Run : {run}/{REPETITIONS}")
                
                enc_output = ENC_DIR / f"{file_path.name}.enc"
                dec_output = DEC_DIR / f"{file_path.name}"
                
                enc_cmd = [
                    sys.executable, "encrypt.py", "encrypt",
                    "--mode", mode,
                    "--input", str(file_path),
                    "--output", str(enc_output),
                    "--public", "benchmark_pub.pem"
                ]
                
                dec_cmd = [
                    sys.executable, "decrypt.py",
                    "--input", str(enc_output),
                    "--output", str(dec_output),
                    "--private", "benchmark_priv.pem"
                ]
                
                status = "OK"
                enc_time = 0.0
                dec_time = 0.0
                throughput = 0.0
                mem_mb = 0.0
                
                try:
                    enc_time, enc_mem = run_command_with_metrics(enc_cmd)
                    dec_time, dec_mem = run_command_with_metrics(dec_cmd)
                    
                    throughput = file_size_mb / enc_time if enc_time > 0 else 0.0
                    peak_mem_bytes = max(enc_mem, dec_mem)
                    mem_mb = peak_mem_bytes / (1024 * 1024)
                    
                    if not dec_output.exists():
                        raise RuntimeError("Decrypted file not found.")
                        
                    orig_hash = compute_sha256(file_path)
                    dec_hash = compute_sha256(dec_output)
                    
                    if orig_hash != dec_hash:
                        raise RuntimeError("SHA-256 hash mismatch between original and decrypted file.")
                    
                    run_metrics["enc_times"].append(enc_time)
                    run_metrics["dec_times"].append(dec_time)
                    run_metrics["throughputs"].append(throughput)
                    run_metrics["memories"].append(mem_mb)
                    
                except Exception as e:
                    print(f"Error during benchmark: {e}")
                    status = "ERROR"
                    
                cleanup_files(enc_output, dec_output)
                    
                with open(RAW_CSV_PATH, "a", newline="") as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        run,
                        file_path.name,
                        f"{file_size_mb:.4f}",
                        mode,
                        f"{enc_time:.4f}" if status == "OK" else "",
                        f"{dec_time:.4f}" if status == "OK" else "",
                        f"{throughput:.4f}" if status == "OK" else "",
                        f"{mem_mb:.4f}" if status == "OK" else "",
                        status
                    ])
                    
            if len(run_metrics["enc_times"]) > 0:
                avg_enc_time = statistics.mean(run_metrics["enc_times"])
                avg_dec_time = statistics.mean(run_metrics["dec_times"])
                avg_throughput = statistics.mean(run_metrics["throughputs"])
                avg_memory = statistics.mean(run_metrics["memories"])
                
                raw_results.append([
                    file_path.name,
                    f"{file_size_mb:.4f}",
                    mode,
                    f"{avg_enc_time:.4f}",
                    f"{avg_dec_time:.4f}",
                    f"{avg_throughput:.4f}",
                    f"{avg_memory:.4f}"
                ])
                
    with open(AVG_CSV_PATH, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(avg_headers)
        writer.writerows(raw_results)
        
    if Path("benchmark_pub.pem").exists():
        Path("benchmark_pub.pem").unlink()
    if Path("benchmark_priv.pem").exists():
        Path("benchmark_priv.pem").unlink()

    print("\nBenchmark completed successfully.")
    print(f"Raw results saved to: {RAW_CSV_PATH}")
    print(f"Average results saved to: {AVG_CSV_PATH}")

if __name__ == "__main__":
    run_benchmark()
