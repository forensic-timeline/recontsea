import csv
import yaml
import os


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


def load_rules_from_yaml(yaml_path):
    """
    Load labeling rules from YAML file.

    Args:
    yaml_path: Path to the YAML file

    Returns:
    List of rule dictionaries
    """
    with open(yaml_path, 'r', encoding='utf-8') as f:
        rules = yaml.safe_load(f)

    print(f"Loaded {len(rules)} rules from {yaml_path}")
    return rules


def match_pattern_strict(text, pattern):
    """
    Match pattern in strict mode (case-sensitive, respects % wildcards).

    Args:
        text: String to check (case-sensitive)
        pattern: Pattern with % wildcards

    Returns:
        True if matched, False otherwise

    Examples:
        '%Mozilla/5.0%' matches 'foo Mozilla/5.0 bar' (anywhere)
        'Mozilla/5.0%' matches 'Mozilla/5.0 bar' (start)
        '%Mozilla/5.0' matches 'foo Mozilla/5.0' (end)
        'Mozilla/5.0' matches 'Mozilla/5.0' (exact)
    """
    # Check wildcard positions
    starts_with_wildcard = pattern.startswith('%')
    ends_with_wildcard = pattern.endswith('%')

    # Remove wildcards
    clean_pattern = pattern.strip('%')

    # Apply matching logic based on wildcards
    if starts_with_wildcard and ends_with_wildcard:
        # %pattern% - can appear anywhere
        return clean_pattern in text
    elif starts_with_wildcard:
        # %pattern - must be at end
        return text.endswith(clean_pattern)
    elif ends_with_wildcard:
        # pattern% - must be at start
        return text.startswith(clean_pattern)
    else:
        # pattern - exact match
        return clean_pattern == text


def match_pattern_moderate(text, pattern):
    """
    Match pattern in moderate mode (case-insensitive, anywhere).

    Args:
        text: String to check
        pattern: Pattern to match

    Returns:
        True if matched, False otherwise
    """
    text_lower = text.lower()
    pattern_lower = str(pattern).lower()
    return pattern_lower in text_lower


def match_filters(text, filters, sensitivity='moderate'):
    """
    Match all filter patterns against text (AND condition).

    Args:
        text: String to check
        filters: List of filter patterns
        sensitivity: 'moderate' (default) or 'strict'

    Returns:
        True if all filters match, False otherwise
    """
    for pattern in filters:
        pattern_str = str(pattern)

        if sensitivity == 'strict':
            # Strict mode: case-sensitive, respect % wildcards
            if not match_pattern_strict(text, pattern_str):
                return False
        else:
            # Moderate mode: case-insensitive, anywhere
            if not match_pattern_moderate(text, pattern_str):
                return False

    return True


def get_labels(text, rules):
    """
    Get labels based on text and rules.

    Args:
        text: String to check
        rules: List of rule dictionaries from YAML

    Returns:
        ground_truth_label
    """
    for rule in rules:
        filters = rule.get('filter', [])
        sensitivity = rule.get('sensitivity', 'moderate')  # Default: moderate

        if match_filters(text, filters, sensitivity):
            return rule['ground_truth_label']

    # Default if there is no match
    return 'benign'


# ===================================
# MAIN CLASS
# ===================================

class LowLevelGT:

    def __init__(self, dataset, rules_file=None):
        self.dataset = dataset
        self.CSV_INPUT = f"results/{dataset}/result-2-log-decoded.csv"
        self.CSV_OUTPUT = f"results/{dataset}/result-3-low-level-ground-truth.csv"

        # Path to the YAML labeling rules file
        self.RULES_FILE = rules_file if rules_file else f"rules-ground-truth/{dataset}.yaml"

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        # Load rules
        labelling_rules = load_rules_from_yaml(self.RULES_FILE)

        total_lines = count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")

        processed = 0
        labeled_count = 0

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)

            # Add new column
            fieldnames = reader.fieldnames + ["ground_truth_label"]
            writer = csv.DictWriter(out, fieldnames=fieldnames)
            writer.writeheader()

            for row in reader:
                processed += 1

                # Get decoded column for matching
                decoded = row.get("decoded", "")

                # Get labels based on pattern matching
                ground_truth_label = get_labels(decoded, labelling_rules)

                row["ground_truth_label"] = ground_truth_label

                if ground_truth_label != 'benign':
                    labeled_count += 1

                writer.writerow(row)

                # Progress every 50,000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        print(f"\nLabelling finished: {processed}/{total_lines} lines processed.")
        print(f"Total labeled (non-benign): {labeled_count}")
        print(f"Total benign: {processed - labeled_count}")
