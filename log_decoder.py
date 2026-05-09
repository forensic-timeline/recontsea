import csv, sys, urllib.parse, base64, binascii, codecs, zlib, gzip, re, json, os
from typing import Optional, Tuple, List


# command keyword buckets (flattened list for scoring)
COMMAND_KEYWORDS = [
    "id","whoami","uname","date","cal","uptime","who","w","last","finger","lsb_release","clear",
    "netstat","ip","ifconfig","ss","netcat",
    "ls","find","chmod","chown","rm","mv","echo","base64","dir","cp","cd",
    "cat","head","tail","less","more","strings","last",
    "wget","curl","fetch",
    "ps","top","tmux","screen",
    "mysql","psql","pgsql","mongo","redis-cli",
    "tar","zip","unzip","7z","rar",
    "bash","sh",".sh",
    "perl","python","python3","php","ruby","lua","gcc",
    "nc","socat","ssh",
    "nmap","masscan",
    "tcpdump","wireshark","tshark","ettercap","dsniff","iptables","ufw","firewalld",
    "hydra","medusa","john","hashcat",
    "gdb","strace","ltrace",
    "systemctl","service","init.d","rc.d","pwd","dpkg","ps","ss"
    "docker","kubectl","helm",
    "git","svn","hg",
    "df", "timedatectl", "lastlog", "history", "watch", "reset"
]

# Build regex: longest-first, escaped
_escaped = sorted([re.escape(k) for k in COMMAND_KEYWORDS], key=len, reverse=True)
# For decoded values (spaces are real): ^(?:keyword)\s
CMD_START_DECODED = re.compile(r'^(?:' + r'|'.join(_escaped) + r')\s', flags=re.IGNORECASE)
# For raw values (may contain + or %20 between keyword and args)
CMD_START_RAW = re.compile(r'^(?:' + r'|'.join(_escaped) + r')(?:(?:\+)|(?:%20)|(?:\s))', flags=re.IGNORECASE)

# Change list to set to make word search faster
KW_SET = set(COMMAND_KEYWORDS)


class LogDecoder:

    def __init__(self, dataset):
        self.dataset = dataset
        self.CSV_INPUT = f"results/{dataset}/result-1-normalization.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-2-log-decoded.csv"

    def count_lines(self, path):
        # fast line count
        cnt = 0
        with open(path, 'r', encoding='utf-8', errors='replace') as f:
            for _ in f:
                cnt += 1
        return cnt

    def score_text_for_commands(self, text: str) -> int:
        if not text:
            return 0
        
        t = text.lower()
        
        try:
            parsed = json.loads(t)
            if isinstance(parsed, list):
                t = " ".join(str(x).lower() for x in parsed)
        except Exception:
            pass

        score = 0
        for kw in KW_SET:
            if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', t):
                score += 1
        return score

    def try_url_unquote(self, s: str) -> Optional[str]:
        try:
            out = urllib.parse.unquote_plus(s)
            return out
        except Exception:
            return None

    def try_hex(self, s: str) -> Optional[str]:
        try:
            if all(c in "0123456789abcdefABCDEF" for c in s) and len(s)%2==0 and len(s)>=8:
                return bytes.fromhex(s).decode('utf-8', errors='replace')
        except Exception:
            pass
        return None

    def try_base64(self, s: str) -> Optional[str]:
        try:
            missing = len(s) % 4
            if missing:
                s = s + ("=" * (4-missing))
            raw = base64.b64decode(s, validate=False)
            try:
                return raw.decode('utf-8', errors='replace')
            except Exception:
                return raw.decode('latin-1', errors='replace')
        except Exception:
            return None

    def try_base64_and_decompress(self, s: str) -> Optional[str]:
        try:
            missing = len(s) % 4
            if missing:
                s = s + ("=" * (4-missing))
            raw = base64.b64decode(s, validate=False)
            try:
                return gzip.decompress(raw).decode('utf-8', errors='replace')
            except Exception:
                pass
            try:
                return zlib.decompress(raw, -zlib.MAX_WBITS).decode('utf-8', errors='replace')
            except Exception:
                pass
        except Exception:
            pass
        return None

    def try_rot13(self, s: str) -> Optional[str]:
        try:
            out = codecs.decode(s, 'rot_13')
            return out
        except Exception:
            return None

    def try_xor_single_byte_hex(self, s: str) -> Optional[Tuple[int,str]]:
        try:
            if all(c in "0123456789abcdefABCDEF" for c in s) and len(s)%2==0:
                ct = bytes.fromhex(s)
                for k in range(1,256):
                    pt = bytes([b ^ k for b in ct])
                    if b"<?php" in pt or b"eval(" in pt or b"system" in pt or b"exec" in pt:
                        return (k, pt.decode('utf-8', errors='replace'))
        except Exception:
            pass
        return None

    def extract_base64_from_php_functions(self, s: str) -> List[str]:
        """
        Ekstrak string base64 dari pattern PHP seperti:
        - base64_decode("...")
        - base64_decode('...')
        - base64_decode(\"...\")
        - base64_decode(\\\"...\\\")
        
        Returns:
        - List of base64 strings found
        """
        results = []
        
        # Patterns for capturing various escape variations
        patterns = [
            # base64_decode("...") atau base64_decode('...')
            r'base64_decode\s*\(\s*["\']([A-Za-z0-9+/=]+)["\']\s*\)',
            # base64_decode(\"...\") - escaped quotes
            r'base64_decode\s*\(\s*\\["\'"]([A-Za-z0-9+/=]+)\\["\']\s*\)',
            # base64_decode(\\\"...\\\") - double escaped quotes
            r'base64_decode\s*\(\s*\\{2,}["\'"]([A-Za-z0-9+/=]+)\\{2,}["\']\s*\)',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, s, re.IGNORECASE)
            results.extend(matches)
        
        return results

    def try_php_base64_decode(self, s: str) -> Optional[Tuple[str, str]]:
        """
        Try to extract and decode base64 from PHP function.
        
        Returns:
        - Tuple of (original_base64, decoded_string) or None
        """
        base64_strings = self.extract_base64_from_php_functions(s)
        
        for b64 in base64_strings:
            decoded = self.try_base64(b64)
            if decoded:
                return (b64, decoded)
        
        return None

    def multi_try_decode(self, s: str) -> List[Tuple[str,str,int]]:
        results = []
        if not s:
            return results
        
        # step 1: try URL decode
        url = self.try_url_unquote(s)
        s2 = url if url and url!=s else s
        if url and url!=s:
            results.append(('url-unquote', s2, self.score_text_for_commands(s2)))
        
        # step 2: try various decoding methods
        for name, fn in [
                         ('hex', self.try_hex), 
                         ('base64', self.try_base64),
                         ('base64+decompress', self.try_base64_and_decompress), 
                         ('rot13', self.try_rot13)]:
            try:
                out = fn(s2)
                if out:
                    sc = self.score_text_for_commands(out)
                    results.append((name, out, sc))
            except Exception:
                pass
        
        # step 3: try XOR single-byte
        xor = self.try_xor_single_byte_hex(s2)
        if xor:
            k, out = xor
            sc = self.score_text_for_commands(out)
            results.append((f'single-byte-xor-key={k}', out, sc))

        # step 4: sort results by highest score
        results.sort(key=lambda x: (x[2],), reverse=True)
        return results

    def choose_best_candidate(self, candidates):
        if not candidates:
            return None
        
        candidates_sorted = sorted(candidates, key=lambda x: (x[2], -len(x[1])), reverse=True)
        top_score = candidates_sorted[0][2]

        if top_score > 0:
            top_candidates = [c for c in candidates_sorted if c[2]==top_score]

            def pref(c):
                text = c[1]
                bonus = 0
                if text.startswith('[') or text.startswith('{') or '"' in text or "'" in text:
                    bonus += 1
                if any(ord(ch) < 32 for ch in text[:50]):
                    bonus -= 1
                return bonus
            
            top_candidates.sort(key=lambda x: pref(x), reverse=True)
            return top_candidates[0]

        preferred_order = ['base64', 'base64+decompress', 'hex', 'rot13', 'uuencode']
        for pref in preferred_order:
            for c in candidates:
                if c[0]==pref:
                    return c
                
        return candidates[0]

    def decode_and_choose(self, encoded: str):
        candidates = self.multi_try_decode(encoded)
        best = self.choose_best_candidate(candidates)
        return candidates, best

    def split_shell_like(self, snippet: str) -> List[str]:
        """Split snippet into shell-like fragments."""
        if not snippet:
            return []
        s = snippet
        s = s.replace('%3B', ';').replace('%3b', ';')
        s = s.replace('%0A', '\n').replace('%0a', '\n').replace('%0D', '\n').replace('%0d', '\n')
        s = s.replace('%26%26', ' && ')
        s = s.replace('%7C', '|').replace('%7c', '|')
        s = re.sub(r'\s+', ' ', s).strip()
        parts = re.split(r'\s*(?:;|&&|\|\||\|)\s*|\n', s)
        return [p.strip() for p in parts if p and p.strip()]

    def detect_rce_query_simple(self, msg_raw: str) -> Optional[Tuple[str, List[str]]]:
        try:
            m = re.search(r'http_request:\s*(?:GET|POST|PUT|DELETE|HEAD)\s+([^ ]*)', msg_raw, flags=re.IGNORECASE)
            raw_uri = m.group(1) if m else None
            if not raw_uri:
                m2 = re.search(r'(/[^\s"\']*\?[^\s"\']*)', msg_raw)
                raw_uri = m2.group(1) if m2 else None
            if not raw_uri or '?' not in raw_uri:
                return None

            raw_uri = raw_uri.replace('~', '%')

            parsed = urllib.parse.urlparse(raw_uri)
            query = parsed.query or ""
            if not query:
                return None

            qs = urllib.parse.parse_qs(query, keep_blank_values=True)

            found_cmds: List[str] = []
            for key, vals in qs.items():
                for raw_val in vals:
                    decoded_val = urllib.parse.unquote_plus(raw_val).strip()
                    if CMD_START_DECODED.match(decoded_val):
                        frags = self.split_shell_like(decoded_val)
                        found_cmds.extend(frags if frags else [decoded_val])
                    else:
                        if isinstance(raw_val, str) and CMD_START_RAW.match(raw_val):
                            frags = self.split_shell_like(urllib.parse.unquote_plus(raw_val))
                            found_cmds.extend(frags if frags else [urllib.parse.unquote_plus(raw_val)])

            if not found_cmds:
                return None

            seen = set()
            deduped = []
            for c in found_cmds:
                if c not in seen:
                    seen.add(c)
                    deduped.append(c)

            snippet = urllib.parse.unquote_plus(query)
            return (snippet, deduped)
        except Exception:
            return None

    def decode_wp_meta_from_msg(self, msg_raw: str) -> str:
        """
        Main decoding function.
        - Detect PHP base64_decode() pattern
        - If user_agent is detected as a tool/script -> perform wp_meta decoding
        - Run detect_rce_query_simple() to add [RCE: "..."] if detected
        """
        original = msg_raw

        decoded_annotation = None
        decoded_final = None
        
        # --- Check base64_decode pattern first ---
        php_decode = self.try_php_base64_decode(msg_raw)
        if php_decode:
            b64_original, b64_decoded = php_decode
            # Cek apakah hasil decode mengandung command keyword
            if self.score_text_for_commands(b64_decoded) > 0:
                decoded_final = f"{original} [DECODED: {b64_decoded}]"
                decoded_annotation = decoded_final
        
        # --- If no decode results yet, try old methods ---
        if not decoded_annotation:
            try:
                user_agent = msg_raw.split("user_agent: ")[1].lower()
            except Exception:
                user_agent = ""

            bad_agents = ["python", "perl", "postman", "curl", "wget", "go-http-client", "java", "shell", "httpclient"]
            matches = [a for a in bad_agents if a in user_agent]
            
            if matches:
                m = re.search(r"[?&]([^=\s]+)=([^&\s]+)", msg_raw)
                if m:
                    param_name = m.group(1)
                    encoded = m.group(2)
                    candidates, best = self.decode_and_choose(encoded)
                    if best:
                        best_text = best[1]
                        for kw in KW_SET:
                            if re.search(r'(?<![a-z0-9])' + re.escape(kw) + r'(?![a-z0-9])', best_text):
                                annex = " | ".join([f"{meth} => {out[:200].replace(chr(10),' ')}" for meth, out, sc in candidates])
                                decoded_annotation = f"{original} [DECODED: {best_text}] [ALL_TRIES: {annex}]"
                                decoded_final = f"{original} [DECODED: {best_text}]"
                    else:
                        annex = " | ".join([f"{meth} => {out[:200].replace(chr(10),' ')}" for meth, out, sc in candidates])
                        if annex:
                            decoded_annotation = f"{original} [DECODE FAILED: tried multi methods] [ALL_TRIES: {annex}]"
                            decoded_final = f"{original} [DECODE FAILED: tried multi methods]"
                        else:
                            decoded_annotation = f"{original} [DECODE FAILED: no candidates]"

        # run RCE detection
        rce = self.detect_rce_query_simple(original)
        if rce:
            snippet, cmd_list = rce
            rce_suffix = f' [RCE: "{snippet}"]'
        else:
            rce_suffix = ""

        if decoded_final:
            return decoded_final + rce_suffix
        else:
            return original + rce_suffix

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        total_lines = self.count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        processed = 0

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, open(self.CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:
            reader = csv.DictReader(f)
            writer = csv.writer(out)
            
            # Add a new column at the beginning
            fieldnames = reader.fieldnames + ["decoded"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in reader:
                processed += 1

                # Retrieve and normalize message column
                normalized = row["normalized"]
                decoded_message = self.decode_wp_meta_from_msg(normalized) if normalized else normalized

                # add results
                row["decoded"] = decoded_message

                writer.writerow(row)
                    
                # Report progress every 50,000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        print(f"Conversion finished: {processed}/{total_lines} lines processed.")
