#!/usr/bin/env python3
from __future__ import annotations

import argparse
import os
import sys
import time
import queue
import multiprocessing as mp
from typing import Optional
from multiprocessing.sharedctypes import Synchronized
from multiprocessing import Event
import bcrypt

# ---------- Colored bullets ----------
try:
    from colorama import init as colorama_init, Fore, Style
    colorama_init(autoreset=True)
    GREEN, RED, YELLOW, CYAN, RESET = Fore.GREEN, Fore.RED, Fore.YELLOW, Fore.CYAN, Style.RESET_ALL
except Exception:
    GREEN = RED = YELLOW = CYAN = RESET = ""

B_OK   = f"{GREEN}[+]{RESET}"
B_ERR  = f"{RED}[-]{RESET}"
B_WARN = f"{YELLOW}[!]{RESET}"
B_INFO = f"{CYAN}[i]{RESET}"

# ---------- Optional tqdm progress ----------
def _get_tqdm():
    try:
        from tqdm import tqdm  # type: ignore
        return tqdm
    except Exception:
        return None

def count_lines_fast(path: str) -> int:
    """Fast line count in binary mode (for ETA)."""
    lines = 0
    chunk = 1024 * 1024
    with open(path, "rb") as f:
        while True:
            buf = f.read(chunk)
            if not buf:
                break
            lines += buf.count(b"\n")
    return lines

# ---------- Worker ----------
def decode_line(raw: bytes, encoding: str) -> str:
    try:
        return raw.decode(encoding, errors="ignore").rstrip("\r\n")
    except Exception:
        return raw.decode("utf-8", errors="ignore").rstrip("\r\n")

def check_password(line: str, encoding: str, bcrypt_hash: bytes) -> bool:
    try:
        return bcrypt.checkpw(line.encode(encoding, errors="ignore"), bcrypt_hash)
    except ValueError as e:
        sys.stderr.write(f"{B_WARN} bcrypt error: {e}\n")
        return False

def process_line(
    raw: bytes,
    encoding: str,
    bcrypt_hash: bytes,
    result_q: mp.Queue,
    found_event,
    progress_counter: Optional[Synchronized[int]],
) -> bool:
    line = decode_line(raw, encoding)
    if not line:
        _inc_progress(progress_counter, 1)
        return False
    if check_password(line, encoding, bcrypt_hash):
        result_q.put(line)
        found_event.set()
        _inc_progress(progress_counter, 1)
        return True
    _inc_progress(progress_counter, 1)
    return False

def worker_scan(
    path: str,
    start: int,
    end: Optional[int],
    bcrypt_hash: bytes,
    encoding: str,
    found_event,
    result_q: mp.Queue,  # plain multiprocessing.Queue
    progress_counter: Optional[Synchronized[int]],
) -> None:
    """
    Scan a slice [start, end) of the wordlist file.
    Exit early if found_event is set or on match (and push to result_q).
    """
    try:
        with open(path, "rb") as fb:
            # Align start to a full line boundary (robust with CRLF/Windows).
            if start > 0:
                fb.seek(start - 1)
                prev = fb.read(1)
                if prev != b"\n":
                    fb.readline()
            else:
                fb.seek(0)
            pos = fb.tell()

            while (end is None) or (pos <= end):
                if found_event.is_set():
                    return

                raw = fb.readline()
                if not raw:
                    break
                pos = fb.tell()

                if process_line(raw, encoding, bcrypt_hash, result_q, found_event, progress_counter):
                    return

    except Exception as e:
        sys.stderr.write(f"{B_WARN} Worker exception: {e}\n")
        found_event.set()
        return

def _inc_progress(counter: Optional[Synchronized[int]], n: int) -> None:
    if counter is None:
        return
    with counter.get_lock():
        counter.value += n

# ---------- Split the file by byte offsets ----------
def split_file_offsets(path: str, workers: int) -> list[tuple[int, Optional[int]]]:
    """
    Return list of (start, end) byte offsets for each worker.
    Boundaries are approximate; workers align to full lines.
    """
    size = os.path.getsize(path)
    if workers <= 1 or size == 0:
        return [(0, None)]
    chunk = size // workers
    offsets: list[tuple[int, Optional[int]]] = []
    start = 0
    for i in range(workers):
        if i == workers - 1:
            offsets.append((start, None))  # last goes to EOF
        else:
            end = start + chunk
            offsets.append((start, end))
            start = end
    return offsets

# ---------- Main progress bar (separate process) ----------
def run_progress_bar(
    total_lines: Optional[int],
    counter: Synchronized[int],
    stop_event,
    label: str = "Testing"
) -> None:
    tqdm = _get_tqdm()
    if tqdm is None or not sys.stdout.isatty():
        # Fallback: simple ASCII bar to stderr
        last = -1
        while not stop_event.is_set():
            time.sleep(0.5)
            cur = counter.value
            if cur != last and total_lines:
                done_pct = (cur / max(total_lines, 1)) * 100
                sys.stderr.write(f"\r{i_bar(20, cur, total_lines)} {cur}/{total_lines} ({done_pct:.1f}%)")
                sys.stderr.flush()
                last = cur
        sys.stderr.write("\n")
        return

    bar = tqdm(total=total_lines, unit="pw", dynamic_ncols=True, desc=label, leave=True)
    last = 0
    while not stop_event.is_set():
        time.sleep(0.1)
        cur = counter.value
        delta = cur - last
        if delta > 0:
            bar.update(delta)
            last = cur
    # final flush
    final_delta = counter.value - last
    if final_delta > 0:
        bar.update(final_delta)
    bar.close()

def i_bar(width: int, cur: int, total: int) -> str:
    if not total:
        return "[" + " " * width + "]"
    filled = int(width * (cur / total))
    return "[" + "#" * filled + "-" * (width - filled) + "]"

# ---------- CLI ----------
def parse_args():
    parser = argparse.ArgumentParser(
        description="Dictionary attack against a bcrypt hash using multiprocessing (defaults to all detected CPU cores)."
    )
    parser.add_argument("-H", "--hash", required=True, help="Bcrypt hash (e.g. $2b$10$...)")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to the wordlist file")
    parser.add_argument("-e", "--encoding", default="utf-8", help="Wordlist encoding (default: utf-8)")
    parser.add_argument(
        "-W", "--workers", type=int, default=os.cpu_count() or 1,
        help="Number of processes (default: all detected CPU cores)"
    )
    parser.add_argument("--no-progress", action="store_true", help="Disable progress bar/ETA")
    return parser.parse_args()

def validate_args(args):
    if not os.path.isfile(args.wordlist):
        print(f"{B_ERR} Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)
    if args.workers < 1:
        args.workers = 1  # -W 0 => single process
    if not args.hash.startswith("$2"):
        print(f"{B_WARN} This does not look like a bcrypt hash ($2a/$2b/$2y). Continuing...", file=sys.stderr)

def get_total_lines(wordlist):
    try:
        return count_lines_fast(wordlist)
    except Exception:
        return None

def launch_progress_process(total_lines, progress_counter, progress_stop):
    progress_proc = mp.Process(
        target=run_progress_bar,
        args=(total_lines, progress_counter, progress_stop, "Testing"),
        daemon=True,
    )
    progress_proc.start()
    return progress_proc

def spawn_workers(wordlist, workers, bcrypt_hash, encoding, found_event, result_q, progress_counter):
    ranges = split_file_offsets(wordlist, workers)
    procs: list[mp.Process] = []
    for (start, end) in ranges:
        p = mp.Process(
            target=worker_scan,
            args=(wordlist, start, end, bcrypt_hash, encoding, found_event, result_q, progress_counter),
        )
        p.start()
        procs.append(p)
    return procs

def collect_result(procs, result_q, found_event):
    match: Optional[str] = None
    try:
        while True:
            try:
                match = result_q.get(timeout=0.05)
                break
            except queue.Empty:
                pass

            if not any(p.is_alive() for p in procs):
                try:
                    match = result_q.get_nowait()
                except queue.Empty:
                    match = None
                break
    except KeyboardInterrupt:
        print(f"\n{B_WARN} Interrupted by user.", file=sys.stderr)
        found_event.set()
    return match

def cleanup(procs, progress_proc, progress_stop):
    progress_stop.set()
    for p in procs:
        p.join(timeout=0.5)
    for p in procs:
        if p.is_alive():
            p.terminate()
    if progress_proc is not None:
        progress_proc.join(timeout=0.5)

def main():
    args = parse_args()
    validate_args(args)
    bcrypt_hash = args.hash.encode("utf-8")
    total_lines: Optional[int] = get_total_lines(args.wordlist)
    found_event = mp.Event()
    progress_stop = mp.Event()
    result_q: mp.Queue = mp.Queue()
    progress_counter: Optional[Synchronized[int]] = None if args.no_progress else mp.Value("i", 0)
    progress_proc: Optional[mp.Process] = None
    if progress_counter is not None:
        progress_proc = launch_progress_process(total_lines, progress_counter, progress_stop)
    procs = spawn_workers(args.wordlist, args.workers, bcrypt_hash, args.encoding, found_event, result_q, progress_counter)
    match = collect_result(procs, result_q, found_event)
    cleanup(procs, progress_proc, progress_stop)
    if match:
        print(f"{B_OK} Match found: {match}")
        sys.exit(0)
    else:
        print(f"{B_ERR} No match found in the provided wordlist.")
        sys.exit(2)

if __name__ == "__main__":
    mp.freeze_support()
    main()
