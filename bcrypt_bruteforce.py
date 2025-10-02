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
def worker_scan(
    path: str,
    start: int,
    end: Optional[int],
    bcrypt_hash: bytes,
    encoding: str,
    found_event: mp.Event,
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
                    # We were in the middle of a line; consume to the end of that line
                    fb.readline()
            else:
                fb.seek(0)
            pos = fb.tell()

            # Process lines until end boundary (include line that starts exactly at 'end')
            while (end is None) or (pos <= end):
                if found_event.is_set():
                    return

                raw = fb.readline()
                if not raw:
                    break
                pos = fb.tell()

                try:
                    line = raw.decode(encoding, errors="ignore").rstrip("\r\n")
                except Exception:
                    line = raw.decode("utf-8", errors="ignore").rstrip("\r\n")

                if not line:
                    _inc_progress(progress_counter, 1)
                    continue

                try:
                    if bcrypt.checkpw(line.encode(encoding, errors="ignore"), bcrypt_hash):
                        result_q.put(line)
                        found_event.set()
                        _inc_progress(progress_counter, 1)
                        return
                except ValueError as e:
                    sys.stderr.write(f"{B_WARN} bcrypt error: {e}\n")
                    found_event.set()
                    return

                _inc_progress(progress_counter, 1)

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
    stop_event: mp.Event,
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
def main():
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
    args = parser.parse_args()

    if not os.path.isfile(args.wordlist):
        print(f"{B_ERR} Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)

    if args.workers < 1:
        args.workers = 1  # -W 0 => single process

    bcrypt_hash = args.hash.encode("utf-8")
    if not args.hash.startswith("$2"):
        print(f"{B_WARN} This does not look like a bcrypt hash ($2a/$2b/$2y). Continuing...", file=sys.stderr)

    # Count lines for progress/ETA (optional)
    total_lines: Optional[int] = None
    try:
        total_lines = count_lines_fast(args.wordlist)
    except Exception:
        total_lines = None

    found_event = mp.Event()
    progress_stop = mp.Event()
    result_q: mp.Queue = mp.Queue()
    progress_counter: Optional[Synchronized[int]] = None if args.no_progress else mp.Value("i", 0)

    # Launch progress process
    progress_proc: Optional[mp.Process] = None
    if progress_counter is not None:
        progress_proc = mp.Process(
            target=run_progress_bar,
            args=(total_lines, progress_counter, progress_stop, "Testing"),
            daemon=True,
        )
        progress_proc.start()

    # Spawn workers
    ranges = split_file_offsets(args.wordlist, args.workers)
    procs: list[mp.Process] = []
    for (start, end) in ranges:
        p = mp.Process(
            target=worker_scan,
            args=(args.wordlist, start, end, bcrypt_hash, args.encoding, found_event, result_q, progress_counter),
        )
        p.start()
        procs.append(p)

    match: Optional[str] = None
    try:
        # Robust collection loop
        while True:
            try:
                match = result_q.get(timeout=0.05)
                break
            except queue.Empty:
                pass

            if not any(p.is_alive() for p in procs):
                # Drain once in case a result arrived just at the end
                try:
                    match = result_q.get_nowait()
                except queue.Empty:
                    match = None
                break
    except KeyboardInterrupt:
        print(f"\n{B_WARN} Interrupted by user.", file=sys.stderr)
        found_event.set()
    finally:
        # Stop progress and join processes
        progress_stop.set()
        for p in procs:
            p.join(timeout=0.5)
        for p in procs:
            if p.is_alive():
                p.terminate()
        if progress_proc is not None:
            progress_proc.join(timeout=0.5)

    if match:
        print(f"{B_OK} Match found: {match}")
        sys.exit(0)
    else:
        print(f"{B_ERR} No match found in the provided wordlist.")
        sys.exit(2)

if __name__ == "__main__":
    mp.freeze_support()
    main()
