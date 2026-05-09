import pandas as pd

import csv
import re
import yaml
import os
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any, Optional
from collections import defaultdict
import time


# ===================================
# LOG TYPE DETECTION
# ===================================

def detect_log_type(desc: str, filename: str) -> Dict[str, Any]:
    """
    Detects log type and extracts important fields.

    If the log is not recognized, it will still extract information that can be used for pattern matching.
    """
    parsed = {}
    lower_desc = desc.lower()
    log_types = []

    # 1. Web/Apache logs - support multiple formats
    if 'access.log' in filename:
        log_types.append('webserver')  # webserver_generic
        log_types.append('proxy')  # proxy_generic
        log_types.append('nginx')  # product nginx
        log_types.append('apache')  # product apache
        _extract_http_fields(desc, parsed)

    # 2. Authentication logs
    elif 'auth.log' in filename:
        log_types.append('linux')
        log_types.append('sshd')
        if 'pam' in lower_desc:
            log_types.append('pam')

    # 3. Syslog
    elif 'syslog' in filename:
        log_types.append('syslog')
        log_types.append('linux')
        if 'systemd' in lower_desc:
            log_types.append('systemd')
        if 'kernel' in lower_desc:
            log_types.append('kernel')
        if 'audit' in lower_desc:
            log_types.append('auditd')

    # 4. If not recognized, try auto-detection based on content.
    else:
        log_types = _auto_detect_log_type(desc, filename)
        # If it looks like an HTTP log, extract the HTTP fields.
        if _looks_like_http_log(desc):
            _extract_http_fields(desc, parsed)

    # Fallback - generic type that can match many rules
    if not log_types:
        log_types.append('generic')

    parsed['log_type'] = log_types
    return parsed


def _looks_like_http_log(desc: str) -> bool:
    """
    Check if the log looks like an HTTP log based on pattern.
    """
    http_indicators = [
        r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b',
        r'HTTP/\d\.\d',
        r'\b(200|301|302|400|401|403|404|500)\b',
        r'user[_-]?agent',
        r'referer',
    ]
    for pattern in http_indicators:
        if re.search(pattern, desc, re.IGNORECASE):
            return True
    return False


def _auto_detect_log_type(desc: str, filename: str) -> List[str]:
    """
    Auto-detect log type based on content and filename.
    """
    log_types = []
    lower_desc = desc.lower()
    lower_filename = filename.lower()
    
    # HTTP/Web patterns
    if _looks_like_http_log(desc):
        log_types.extend(['webserver', 'proxy', 'generic_http'])
    
    # Windows Event Log patterns
    if 'eventid' in lower_desc or 'event_id' in lower_desc:
        log_types.append('windows')
    if 'security' in lower_filename and 'evtx' in lower_filename:
        log_types.extend(['windows', 'security'])
    
    # Firewall patterns
    if any(x in lower_desc for x in ['iptables', 'firewall', 'drop', 'accept', 'reject']):
        log_types.append('firewall')
    
    # DNS patterns
    if 'dns' in lower_filename or 'query' in lower_desc and 'type' in lower_desc:
        log_types.append('dns')
    
    # Application patterns
    if 'application' in lower_filename or 'app' in lower_filename:
        log_types.append('application')
    
    # JSON log patterns
    if desc.strip().startswith('{') and desc.strip().endswith('}'):
        log_types.append('json')
    
    return log_types


def _extract_http_fields(desc: str, parsed: Dict[str, Any]):
    """
    Extract HTTP-related fields from the log description.
    """
    # Extract HTTP method
    method_match = re.search(r'\b(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b', desc)
    if method_match:
        parsed['cs-method'] = method_match.group(1)

    # Extract URI - try different patterns
    uri_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s]+)\s+HTTP', desc)
    if uri_match:
        uri = uri_match.group(2)
        if uri.startswith("/"):
            parsed['c-uri'] = uri
    else:
        uri_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\s+([^\s"]+)', desc)
        if uri_match:
            uri = uri_match.group(2)
            if uri.startswith("/"):
                parsed['c-uri'] = uri

    # Extract status code
    status_match = re.search(r'code:\s*(\d{3})', desc)
    if status_match:
        parsed['sc-status'] = status_match.group(1)
    else:
        status_match = re.search(r'\s(\d{3})\s', desc)
        if status_match:
            parsed['sc-status'] = status_match.group(1)

    # Extract User Agent
    ua_match = re.search(r'user_agent:\s*(.+?)(?:\s+\w+:|$)', desc)
    if ua_match:
        parsed['cs-user-agent'] = ua_match.group(1).strip()
    else:
        ua_match = re.search(r'"([^"]+)"', desc)
        if ua_match:
            ua = ua_match.group(1)
            if re.search(r"(mozilla|curl|wget|sqlmap|nikto)", ua, re.IGNORECASE):
                parsed['cs-user-agent'] = ua

    # Extract Referer
    referer_match = re.search(r'referer:\s*(.+?)(?:\s+\w+:|$)', desc)
    if referer_match:
        parsed['cs-referer'] = referer_match.group(1).strip()


# ===================================
# SIGMA MATCHER
# ===================================

class SigmaMatcher:
    """
    Universal Sigma rule matcher with flexible mode support
    """

    def __init__(self, rule_file: str, flexible_mode: bool = True):
        with open(rule_file, 'r', encoding='utf-8') as f:
            self.rule_data = yaml.safe_load(f)

        self.title = self.rule_data.get('title', 'Unknown')
        self.description = self.rule_data.get('description', '')
        self.level = self.rule_data.get('level', 'medium')
        self.tags = self.rule_data.get('tags', [])
        self.detection = self.rule_data.get('detection', {})
        self.logsource = self.rule_data.get('logsource', {})
        self.flexible_mode = flexible_mode

    def match(self, log_entry: Dict[str, Any]) -> bool:
        """Check if log entry matches the rule"""
        if not log_entry:
            return False
    
        # ===== LOGSOURCE FILTER (Skip if flexible_mode=True) =====
        if not self.flexible_mode and self.logsource:
            if not self._check_logsource(log_entry):
                return False

        # ===== DETECTION PROCESS =====
        condition = self.detection.get('condition', '').lower().strip()
    
        selections = {}
        for key, value in self.detection.items():
            if key == 'condition':
                continue
            selections[key.lower()] = self._match_selection(value, log_entry)
    
        return self._evaluate_condition(condition, selections)

    def _check_logsource(self, log_entry: Dict[str, Any]) -> bool:
        """
        Check if log_entry matches the expected logsource for the rule.
        Return True if it matches or if there is no logsource constraint.
        """
        expected_category = self.logsource.get("category", "").lower()
        expected_product = self.logsource.get("product", "").lower()
        expected_service = self.logsource.get("service", "").lower()
        
        log_types = log_entry.get("log_type", [])
        if isinstance(log_types, str):
            log_types = [log_types]
        
        log_types_lower = [lt.lower() for lt in log_types]

        if expected_category:
            if not any(expected_category in lt for lt in log_types_lower):
                return False
        
        if expected_product:
            if expected_service:
                if not any(expected_service in lt for lt in log_types_lower):
                    if not any(expected_product in lt for lt in log_types_lower):
                        return False

        return True

    def _match_selection(self, selection, log_entry: Dict) -> bool:
        """
        Match selection against log entries.
        In flexible mode, always search across all possible fields.
        """
        # Build search fields - in flexible mode, use all available fields
        search_fields = self._get_search_fields(log_entry)
        
        # 1) If selection is a list (OR condition - any pattern matches)
        if isinstance(selection, list):
            for pattern in selection:
                pattern_lower = str(pattern).lower()
                if any(pattern_lower in field for field in search_fields):
                    return True
            return False
    
        # 2) If selection is a raw string
        if isinstance(selection, str):
            pattern_lower = selection.lower()
            return any(pattern_lower in field for field in search_fields)
    
        # 3) Selection must be dict
        if not isinstance(selection, dict):
            return False
    
        # 4) Handle dict-based rules
        for field, patterns in selection.items():
            # Check for '|all' modifier (ALL patterns must match)
            if field == '|all':
                patterns = patterns if isinstance(patterns, list) else [patterns]
                # ALL patterns must be found in search_fields
                for pattern in patterns:
                    pattern_lower = str(pattern).lower()
                    if not any(pattern_lower in f for f in search_fields):
                        return False
                return True
            
            # Check for '|any' modifier (ANY pattern matches - same as list)
            if field == '|any':
                patterns = patterns if isinstance(patterns, list) else [patterns]
                for pattern in patterns:
                    pattern_lower = str(pattern).lower()
                    if any(pattern_lower in f for f in search_fields):
                        return True
                return False
            
            # Regular field matching
            field_name, modifier = self._parse_field(field)
            patterns = patterns if isinstance(patterns, list) else [patterns]

            # In flexible mode, search for the field in log_entry or fallback to desc
            log_value = self._get_field_value(log_entry, field_name)
    
            if not log_value:
                if not all(str(p).lower() == "null" for p in patterns):
                    return False
    
            for p in patterns:
                if str(p).lower() == "null" and log_value != "":
                    return False
    
            pattern_matched = False
            for p in patterns:
                if self._match_pattern(log_value, str(p).lower(), modifier):
                    pattern_matched = True
                    break
            
            if not pattern_matched:
                return False
    
        return True

    def _get_search_fields(self, log_entry: Dict) -> List[str]:
        """
        Get all searchable fields from the log entry.
        In flexible mode, always include all possible fields.
        """
        search_fields = []
        
        # Always include desc as the main fallback
        if 'desc' in log_entry:
            search_fields.append(str(log_entry.get('desc', '')).lower())
        
        # Include HTTP-related fields if present
        http_fields = ['c-uri', 'cs-uri-query', 'cs-user-agent', 'cs-referer', 'cs-method']
        for field in http_fields:
            if field in log_entry and log_entry[field]:
                search_fields.append(str(log_entry[field]).lower())
        
        # Include additional fields if present
        extra_fields = ['command', 'commandline', 'process', 'image', 'parentimage']
        for field in extra_fields:
            if field in log_entry and log_entry[field]:
                search_fields.append(str(log_entry[field]).lower())
        
        return search_fields if search_fields else ['']

    def _get_field_value(self, log_entry: Dict, field_name: str) -> str:
        """
        Get value from a specific field.
        If the field is not present, fallback to desc.
        """
        # Direct match
        if field_name in log_entry:
            return str(log_entry[field_name]).lower()
        
        # Common field name mappings
        field_mappings = {
            'uri': 'c-uri',
            'url': 'c-uri',
            'query': 'cs-uri-query',
            'useragent': 'cs-user-agent',
            'user_agent': 'cs-user-agent',
            'c-useragent': 'cs-user-agent',
            'cs-useragent': 'cs-user-agent',
            'c-user-agent': 'cs-user-agent',
            'method': 'cs-method',
            'status': 'sc-status',
            'message': 'desc',
            'msg': 'desc',
            'commandline': 'desc',
            'command': 'desc',
        }
        
        mapped_field = field_mappings.get(field_name.lower())
        if mapped_field and mapped_field in log_entry:
            return str(log_entry[mapped_field]).lower()
        
        # Fallback to desc if the field is not found (flexible matching)
        if self.flexible_mode and 'desc' in log_entry:
            return str(log_entry['desc']).lower()
        
        return ''

    def _parse_field(self, field: str):
        """
        Parse field name and modifier from Sigma rule field.
        Example: 'CommandLine|contains' -> ('CommandLine', 'contains')
                'CommandLine|contains|all' -> ('CommandLine', 'contains')
                'CommandLine' -> ('CommandLine', None)
        """
        if "|" not in field:
            return (field, None)
        parts = field.split("|")
        field_name = parts[0]
        modifier = parts[1] if len(parts) > 1 else None
        return (field_name, modifier)

    def _match_pattern(self, value: str, pattern: str, modifier: str = None):
        if modifier == "contains":
            return pattern in value
        if modifier == "startswith":
            return value.startswith(pattern)
        if modifier == "endswith":
            return value.endswith(pattern)
        if modifier == "re":
            return bool(re.search(pattern, value))
        
        # Handle wildcard patterns (*) from Sigma rules
        if '*' in pattern:
            # Convert Sigma wildcard to regex - anchor for exact match with wildcards
            regex_pattern = '^' + re.escape(pattern).replace(r'\*', '.*') + '$'
            return bool(re.search(regex_pattern, value, re.IGNORECASE))
        
        # Default: EXACT match (case insensitive) for Sigma rules without modifier
        # This prevents 'Mozilla/5.0' from matching 'Mozilla/5.0 (Windows...)'
        return pattern == value

    def _evaluate_condition(self, condition: str, selections: Dict[str, bool]) -> bool:
        if not condition:
            return any(selections.values())
    
        condition = condition.lower().strip()
        
        not_one_of_pattern = re.search(r'not (\d+) of (\w+)\*?', condition)
        if not_one_of_pattern:
            count = int(not_one_of_pattern.group(1))
            prefix = not_one_of_pattern.group(2)
            matching_selections = [v for k, v in selections.items() if k.startswith(prefix)]
            if matching_selections:
                filter_result = sum(matching_selections) >= count
                condition = re.sub(r'not \d+ of \w+\*?', str(not filter_result), condition)
        
        all_of_pattern = re.search(r'all of (\w+)\*?', condition)
        if all_of_pattern:
            prefix = all_of_pattern.group(1)
            matching_selections = [v for k, v in selections.items() if k.startswith(prefix)]
            if matching_selections:
                result = all(matching_selections)
                condition = re.sub(r'all of \w+\*?', str(result), condition)
        
        one_of_pattern = re.search(r'(\d+) of (\w+)\*?', condition)
        if one_of_pattern:
            count = int(one_of_pattern.group(1))
            prefix = one_of_pattern.group(2)
            matching_selections = [v for k, v in selections.items() if k.startswith(prefix)]
            if matching_selections:
                result = sum(matching_selections) >= count
                condition = re.sub(r'\d+ of \w+\*?', str(result), condition)
        
        if "all of them" in condition:
            condition = condition.replace("all of them", str(all(selections.values())))
        
        if "1 of them" in condition:
            condition = condition.replace("1 of them", str(any(selections.values())))
        if "any of them" in condition:
            condition = condition.replace("any of them", str(any(selections.values())))
        
        for key, result in selections.items():
            condition = re.sub(rf"\b{re.escape(key)}\b", str(result), condition)
        
        try:
            result = bool(eval(condition))
            return result
        except Exception as e:
            # Don't print a warning for each row
            return any(selections.values())


# ===================================
# SIGMA RULES LOADER
# ===================================

class SigmaRulesLoader:
    """Load dan manage Sigma rules"""
    
    def __init__(self, rules_dir: str = 'sigma-rules', flexible_mode: bool = True):
        self.rules_dir = rules_dir
        self.flexible_mode = flexible_mode
        self.matchers = []
        self.load_rules()
    
    def load_rules(self):
        """Load semua rules dari directory"""
        rules_path = Path(self.rules_dir)
        
        if not rules_path.exists():
            print(f"⚠️  Rules directory not found: {self.rules_dir}")
            return
        
        mode_str = "FLEXIBLE" if self.flexible_mode else "STRICT"
        print(f"\n📂 Loading Sigma rules from: {self.rules_dir} (Mode: {mode_str})")
        print("-" * 80)
        
        loaded_count = 0
        for rule_file in rules_path.glob('**/*.yml'):
            try:
                matcher = SigmaMatcher(str(rule_file), flexible_mode=self.flexible_mode)
                self.matchers.append({
                    'matcher': matcher,
                    'title': matcher.title,
                    'level': matcher.level,
                })
                loaded_count += 1
                
                print(f"✅ {matcher.title} [{matcher.level}]")
            
            except Exception as e:
                print(f"⚠️  Error loading {rule_file}: {e}")
                pass
        
        print(f"\n📋 Total rules loaded: {len(self.matchers)}")
    
    def check_row(self, parsed_row: Dict[str, Any]) -> List[Dict[str, str]]:
        matches = []
    
        for rule_info in self.matchers:
            matcher = rule_info['matcher']
    
            if matcher.match(parsed_row):
                matches.append({
                    'rule_title': matcher.title,
                    'rule_level': matcher.level,
                })
    
        return matches


# ===================================
# HELPER FUNCTIONS
# ===================================

def count_lines(path):
    # fast line count
    cnt = 0
    with open(path, 'r', encoding='utf-8', errors='replace') as f:
        for _ in f:
            cnt += 1
    return cnt


def extract_sigma_priority(sigma_value: str):
    """
    Select the highest rule based on severity.
    Input format: "RuleName[severity] | OtherRule[severity]"
    Priority order: critical > high > medium > low > informational
    """

    if not sigma_value or not sigma_value.strip():
        return ""

    items = [s.strip() for s in sigma_value.split("|")]

    priority = {
        "critical": 5,
        "high": 4,
        "medium": 3,
        "low": 2,
        "informational": 1
    }

    best_item = None
    best_score = 0

    for item in items:
        if "[" in item and "]" in item:
            severity = item[item.rfind("[")+1 : item.rfind("]")].lower().strip()
        else:
            continue
        
        if severity in priority:
            score = priority[severity]

            if score > best_score:
                best_score = score
                best_item = item

    return best_item or ""


# ===================================
# MAIN CLASS
# ===================================

class LowLevelPredict:

    def __init__(self, dataset, rules_dir='rules-sigma', flexible_mode=False):
        self.dataset = dataset
        self.CSV_INPUT = f"results/{dataset}/result-2-log-decoded.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-4-low-level-predict.csv"
        self.rules_dir = rules_dir
        self.flexible_mode = flexible_mode

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        # Load rules with flexible mode (from the configuration above)
        rules_loader = SigmaRulesLoader(rules_dir=self.rules_dir, flexible_mode=self.flexible_mode)

        if not rules_loader.matchers:
            print("\n⚠️  No rules loaded! Exiting...")
            return

        total_lines = count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        processed = 0
        matched_rows = 0

        start_time = time.time()
        last_checkpoint = start_time

        benign = 0

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:
            
            reader = csv.DictReader(f)
            
            fieldnames = reader.fieldnames + ["label_candidates","label_predict"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()
            
            for row in reader:
                processed += 1
                decoded = row.get("decoded", "")
                display_name = row.get("display_name", "")
                
                parsed = detect_log_type(decoded, display_name)
                log_entry = {
                    "desc": decoded,
                    "log_type": parsed["log_type"],
                    "cs-method": parsed.get("cs-method", ""),
                    "c-uri": parsed.get("c-uri", ""),
                    "sc-status": parsed.get("sc-status", ""),
                    "cs-user-agent": parsed.get("cs-user-agent", ""),
                    "service": parsed.get("service", ""),
                }
                matches = rules_loader.check_row(log_entry)
                if matches:
                    matched_rows += 1
                    detection_str = " | ".join([
                        f"{m['rule_title']}[{m['rule_level']}]" 
                        for m in matches
                    ])
                else:
                    detection_str = ""
                sigma_result = extract_sigma_priority(detection_str)
                if not sigma_result:
                    sigma_result = 'benign'
                    benign += 1

                if not detection_str:
                    detection_str = 'benign'
                
                row["label_candidates"] = detection_str
                row["label_predict"] = sigma_result
                writer.writerow(row)
                    
                # Progress every 10,000 lines with time
                if processed % 10000 == 0:
                    current_time = time.time()
                    batch_time = current_time - last_checkpoint
                    total_elapsed = current_time - start_time
                    avg_per_10k = total_elapsed / (processed / 10000)
                    remaining = (total_lines - processed) / 10000 * avg_per_10k
                    
                    # Format total elapsed as minutes:seconds
                    elapsed_min = int(total_elapsed // 60)
                    elapsed_sec = total_elapsed % 60
                    
                    print(f"Processed {processed:,}/{total_lines:,} ({processed/total_lines:.2%}) | "
                          f"Batch: {batch_time:.2f}s | "
                          f"Total: {elapsed_min}m {elapsed_sec:.1f}s | "
                          f"ETA: {remaining/60:.1f} min")
                    
                    last_checkpoint = current_time

        total_time = time.time() - start_time
        print(f"\nLabelling finished: {processed:,}/{total_lines:,} lines processed.")
        print(f"Total time: {total_time/60:.2f} minutes ({total_time/processed*1000:.2f}ms per row)")
        print(f"Total benign: {benign} event")
        print(f"Total attack: {total_lines-benign} event")
