import os
import sys
import json
import re
import logging
from http.server import HTTPServer, BaseHTTPRequestHandler

# Setup secure logging (no sensitive text or secrets logged)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [PresidioService] %(message)s"
)
logger = logging.getLogger("presidio_service")

PRESIDIO_VERSION = "2.2.35"
HAS_OFFICIAL_PRESIDIO = False
official_analyzer = None

# Attempt to load official presidio_analyzer if available
try:
    import presidio_analyzer
    from presidio_analyzer import AnalyzerEngine
    official_analyzer = AnalyzerEngine()
    HAS_OFFICIAL_PRESIDIO = True
    PRESIDIO_VERSION = getattr(presidio_analyzer, "__version__", "2.2.35")
    logger.info(f"Loaded official Microsoft Presidio AnalyzerEngine v{PRESIDIO_VERSION}")
except Exception:
    HAS_OFFICIAL_PRESIDIO = False
    logger.info("Using embedded Python Microsoft Presidio Pattern & Entity Engine")

# ==============================================================================
# Embedded Python Microsoft Presidio Entity Recognizers & Rule Engine
# ==============================================================================

# Luhn validation for credit card numbers
def validate_luhn(number_str: str) -> bool:
    digits = re.sub(r"\D", "", number_str)
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for i, char in enumerate(reverse_digits):
        n = int(char)
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0

PATTERNS = [
    # EMAIL
    (
        "EMAIL_ADDRESS",
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        0.95,
        None
    ),
    # US SSN
    (
        "US_SSN",
        re.compile(r"\b(?!000|666|9\d{2})\d{3}[- ](?!00)\d{2}[- ](?!0000)\d{4}\b"),
        0.95,
        None
    ),
    # CREDIT CARD (with Luhn check)
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:4\d{3}|5[1-5]\d{2}|6011|3[47]\d{2})[- ]?\d{4}[- ]?\d{4}[- ]?\d{1,4}\b"),
        0.90,
        lambda val: validate_luhn(val)
    ),
    # IP ADDRESS (IPv4)
    (
        "IP_ADDRESS",
        re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"),
        0.85,
        None
    ),
    # PHONE NUMBER
    (
        "PHONE_NUMBER",
        re.compile(r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        0.80,
        lambda val: len(re.sub(r"\D", "", val)) in (10, 11)
    ),
    # IBAN
    (
        "IBAN_CODE",
        re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b"),
        0.90,
        None
    ),
    # CRYPTO WALLET
    (
        "CRYPTO",
        re.compile(r"\b(?:0x[a-fA-F0-9]{40}|(?:1|3|bc1)[a-zA-Z0-9]{25,42})\b"),
        0.85,
        None
    ),
    # US PASSPORT
    (
        "US_PASSPORT",
        re.compile(r"\b[A-Z0-9]{9}\b"),
        0.60,
        lambda val: any(c.isalpha() for c in val) and any(c.isdigit() for c in val)
    ),
    # URL
    (
        "URL",
        re.compile(r"\bhttps?://[A-Za-z0-9.-]+(?::\d+)?(?:/[^\s<>\"]*)?"),
        0.85,
        None
    ),
    # DATE_TIME with DOB context
    (
        "DATE_TIME",
        re.compile(r"\b(?:19\d{2}|20\d{2})[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])\b|\b(?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])[-/.](?:19\d{2}|20\d{2})\b"),
        0.75,
        None
    ),
]

# Common names for PERSON recognition fallback
PERSON_PATTERN = re.compile(
    r"\b(?:Customer|Author|Supervisor|Name|Contact|Owner|User|Developer|Engineer|Dr\.|Mr\.|Ms\.|Mrs\.)\s+([A-Z][a-z]{2,}(?:\s+[A-Z][a-z]{2,})?)\b"
)

LOCATION_PATTERN = re.compile(
    r"\b\d{1,5}\s+[A-Z][a-z]+\s+(?:Street|St|Avenue|Ave|Boulevard|Blvd|Road|Rd|Lane|Ln|Drive|Dr|Way|Court|Ct|Plaza|Pkwy)\b",
    re.IGNORECASE
)

def run_embedded_presidio(text: str, score_threshold: float = 0.4):
    results = []
    if not text:
        return results

    # Standard patterns
    for entity_type, pattern, score, validator in PATTERNS:
        if score < score_threshold:
            continue
        for match in pattern.finditer(text):
            val = match.group(0)
            if validator and not validator(val):
                continue
            results.append({
                "entity": entity_type,
                "text": val,
                "start": match.start(),
                "end": match.end(),
                "score": round(score, 4)
            })

    # PERSON pattern
    for match in PERSON_PATTERN.finditer(text):
        full_val = match.group(0)
        person_name = match.group(1)
        start = match.start(1)
        end = match.end(1)
        results.append({
            "entity": "PERSON",
            "text": person_name,
            "start": start,
            "end": end,
            "score": 0.85
        })

    # LOCATION pattern
    for match in LOCATION_PATTERN.finditer(text):
        val = match.group(0)
        results.append({
            "entity": "LOCATION",
            "text": val,
            "start": match.start(),
            "end": match.end(),
            "score": 0.82
        })

    # Sort and eliminate exact duplicates
    results.sort(key=lambda r: (r["start"], -r["end"]))
    deduped = []
    seen_spans = set()
    for r in results:
        key = (r["start"], r["end"], r["entity"])
        if key not in seen_spans:
            seen_spans.add(key)
            deduped.append(r)

    return deduped


class PresidioHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Prevent logging prompts or sensitive entities to stdout
        pass

    def _send_json(self, status_code: int, data: dict):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.end_headers()

    def do_GET(self):
        path = self.path.split("?")[0]
        if path in ("/health", "/api/health"):
            self._send_json(200, {
                "status": "healthy",
                "available": True,
                "service": "Microsoft Presidio",
                "version": PRESIDIO_VERSION,
                "engine": "official" if HAS_OFFICIAL_PRESIDIO else "embedded-python"
            })
        elif path == "/":
            self._send_json(200, {
                "service": "Microsoft Presidio Analyzer API",
                "status": "online",
                "available": True,
                "version": PRESIDIO_VERSION
            })
        else:
            self._send_json(404, {"error": "Not found"})

    def do_POST(self):
        path = self.path.split("?")[0]
        if path == "/analyze":
            try:
                content_length = int(self.headers.get("Content-Length", 0))
                raw_body = self.rfile.read(content_length).decode("utf-8")
                payload = json.loads(raw_body) if raw_body else {}
                text = payload.get("text", "")
                language = payload.get("language", "en")
                score_threshold = float(payload.get("score_threshold", 0.4))

                if not text:
                    self._send_json(200, {"results": []})
                    return

                if HAS_OFFICIAL_PRESIDIO and official_analyzer:
                    official_res = official_analyzer.analyze(
                        text=text,
                        language=language,
                        score_threshold=score_threshold
                    )
                    results = []
                    for r in official_res:
                        results.append({
                            "entity": r.entity_type,
                            "text": text[r.start:r.end],
                            "start": r.start,
                            "end": r.end,
                            "score": round(float(r.score), 4)
                        })
                else:
                    results = run_embedded_presidio(text, score_threshold)

                self._send_json(200, {"results": results})
            except Exception as e:
                logger.error(f"Error processing /analyze request: {type(e).__name__}")
                self._send_json(500, {"error": "Failed to analyze text"})
        else:
            self._send_json(404, {"error": "Not found"})


def run_server():
    port = int(os.environ.get("PRESIDIO_PORT", 5001))
    server_address = ("127.0.0.1", port)
    httpd = HTTPServer(server_address, PresidioHandler)
    logger.info(f"Microsoft Presidio Service listening on http://127.0.0.1:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    logger.info("Presidio service stopped.")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test-check":
        print(f"Presidio Python service ready. Engine: {'official' if HAS_OFFICIAL_PRESIDIO else 'embedded'}")
        sys.exit(0)
    run_server()
