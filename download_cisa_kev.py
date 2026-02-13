#!/usr/bin/env python3
"""
Download Known Exploited Vulnerabilities (KEV) JSON from CISA.

Usage:
  python download_cisa_kev.py [--output PATH] [--force]

By default the file is saved as `known_exploited_vulnerabilities.json` in the current directory.
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error
import os
import ssl
import urllib.error as urlerror

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def download(url, timeout=15, retries=3, backoff=1.5, cafile=None, insecure=False):
    """Download bytes from url with optional cafile or insecure flag.

    If `cafile` is provided it will be used to create an SSLContext. If
    `insecure` is True the SSL verification will be disabled (not recommended
    for production).
    """
    last_exc = None
    ctx = None
    if insecure:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    elif cafile:
        ctx = ssl.create_default_context(cafile=cafile)

    for attempt in range(1, retries + 1):
        try:
            # pass context when present
            if ctx is not None:
                with urllib.request.urlopen(url, timeout=timeout, context=ctx) as resp:
                    if getattr(resp, 'status', 200) != 200:
                        raise urllib.error.HTTPError(url, getattr(resp, 'status', 0), getattr(resp, 'reason', ''), resp.headers, None)
                    return resp.read()
            else:
                with urllib.request.urlopen(url, timeout=timeout) as resp:
                    if getattr(resp, 'status', 200) != 200:
                        raise urllib.error.HTTPError(url, getattr(resp, 'status', 0), getattr(resp, 'reason', ''), resp.headers, None)
                    return resp.read()
        except Exception as e:
            last_exc = e
            if attempt == retries:
                break
            time.sleep(backoff * attempt)
    raise last_exc


def main():
    parser = argparse.ArgumentParser(description="Download CISA KEV JSON feed")
    parser.add_argument("--output", "-o", default="known_exploited_vulnerabilities.json", help="Output file path")
    parser.add_argument("--force", "-f", action="store_true", help="Overwrite existing file")
    parser.add_argument("--retries", type=int, default=3, help="Number of download attempts")
    parser.add_argument("--insecure", action="store_true", help="Disable SSL verification (insecure)")
    parser.add_argument("--cafile", default=None, help="Path to CA bundle file to use for verification")
    args = parser.parse_args()

    outpath = args.output

    if os.path.exists(outpath) and not args.force:
        print(f"Error: '{outpath}' already exists. Use --force to overwrite.", file=sys.stderr)
        sys.exit(1)

    try:
        raw = download(URL, retries=args.retries, cafile=args.cafile, insecure=args.insecure)
    except Exception as e:
        # If the failure looks like an SSL certificate verification problem,
        # try to retry using the certifi CA bundle if available.
        is_ssl_err = False
        try:
            import ssl as _ssl
            if isinstance(e, _ssl.SSLError):
                is_ssl_err = True
        except Exception:
            pass

        # urllib can wrap SSL errors inside URLError.reason
        try:
            if isinstance(e, urlerror.URLError) and getattr(e, 'reason', None):
                reason_str = str(e.reason)
                if 'CERTIFICATE_VERIFY_FAILED' in reason_str or 'certificate verify failed' in reason_str:
                    is_ssl_err = True
        except Exception:
            pass

        if is_ssl_err and not args.insecure and not args.cafile:
            try:
                import certifi
                print("SSL verification failed; retrying using certifi CA bundle...", file=sys.stderr)
                raw = download(URL, retries=args.retries, cafile=certifi.where(), insecure=False)
            except Exception as e2:
                print(f"Failed using certifi fallback: {e2}", file=sys.stderr)
                print(f"Original error: {e}", file=sys.stderr)
                sys.exit(2)
        else:
            print(f"Failed to download from {URL}: {e}", file=sys.stderr)
            sys.exit(2)

    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as e:
        print(f"Downloaded data is not valid JSON: {e}", file=sys.stderr)
        sys.exit(3)

    try:
        with open(outpath, "w", encoding="utf-8") as f:
            json.dump(parsed, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to write to '{outpath}': {e}", file=sys.stderr)
        sys.exit(4)

    print(f"Saved KEV JSON to '{outpath}'")


if __name__ == "__main__":
    main()
