import pandas as pd
import csv
import re
import os
import sys

csv.field_size_limit(sys.maxsize)


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


def remove_severity(value):
    """
    Removes the severity level from a string.
    Example: 'Rule Name[high]' -> 'Rule Name'
    """
    if not value:
        return value
    return re.sub(r'\[(critical|high|medium|low|informational)\]$', '', value).strip()


def extract_severity(value):
    """
    Extract severity level from a string.
    Example: 'Rule Name[high]' -> 'high'
    """
    if not value:
        return ''
    match = re.search(r'\[(critical|high|medium|low|informational)\]$', value, re.IGNORECASE)
    if match:
        return match.group(1).lower()
    return ''


def get_severity_priority(severity):
    """
    Return priority score for a given severity level.
    Higher score = higher priority.
    """
    priority_map = {
        'critical': 5,
        'high': 4,
        'medium': 3,
        'low': 2,
        'informational': 1,
        '': 0  # No severity
    }
    return priority_map.get(severity.lower(), 0)


def write_group(writer, row, count, event_ids):
    """
    Write one group to CSV.

    Args:
        writer: csv.writer object
        row: dict of the first row in the group
        count: number of rows in the group
        event_ids: list of event_ids in the group
    """
    label_predict = row.get('label_predict', '')
    label_predict_clean = remove_severity(label_predict)
    severity = extract_severity(label_predict)

    writer.writerow([
        row.get('event_id', ''),
        row.get('datetime', ''),
        row.get('display_name', ''),
        row.get('decoded', ''),
        label_predict_clean,
        severity,
        count,
        '|'.join(event_ids)
    ])


# ===================================
# MAIN CLASS
# ===================================

class HighLevelPredict:

    def __init__(self, dataset, output2_selection_mode='severity'):
        self.dataset = dataset
        self.CSV_INPUT = f"results/{dataset}/result-4-low-level-predict.csv"
        self.CSV_OUTPUT_ALL = f"results/{dataset}/result-6-2-high-level-predict.csv"
        self.CSV_OUTPUT_UNIQUE = f"results/{dataset}/result-6-2-high-level-predict-unique-datetime.csv"

        # Output 2 Selection Mode
        # "severity" = Get the row with the highest severity per datetime
        # "first" = Get the first row that appears per datetime
        self.OUTPUT2_SELECTION_MODE = output2_selection_mode

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        written_all = self._run_output1()
        written_unique = self._run_output2()

        self._print_summary(written_all, written_unique)

    def _run_output1(self):
        """Output 1: All Predictions (with grouping)"""

        # Write to CSV - Version 1: All predictions with grouping
        total_lines = count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")
        # print("\n" + "="*80)
        # print("OUTPUT 1: All Predictions (with grouped duplicate rows)")
        # print("="*80)

        processed = 0
        written_all = 0
        skipped_benign = 0
        skipped_duplicate = 0

        # Group tracking
        last_label_predict = None
        first_group_row = None
        group_count = 0
        group_event_ids = []

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT_ALL, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Header
            writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'label_predict', 'severity', 'group_count', 'low_event_ids'])

            for row in reader:
                processed += 1

                event_id = row.get('event_id', '')
                label_predict = row.get('label_predict', '')
                label_predict_clean = remove_severity(label_predict)

                # 1. Skip if label_predict is 'benign'
                if label_predict_clean.lower() == 'benign':
                    skipped_benign += 1
                    continue

                # 2. Check if it's the same as the previous group (consecutive duplicates)
                if label_predict_clean == last_label_predict:
                    # Still in the same group - add to the group
                    group_count += 1
                    group_event_ids.append(str(event_id))
                    skipped_duplicate += 1
                    continue

                # 3. Different sigma - write previous group (if any)
                if first_group_row is not None:
                    write_group(writer, first_group_row, group_count, group_event_ids)
                    written_all += 1

                # 4. Start a new group
                last_label_predict = label_predict_clean
                first_group_row = row
                group_count = 1
                group_event_ids = [str(event_id)]

                # Progress every 50,000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

            # Write the last group (don't forget!)
            if first_group_row is not None:
                write_group(writer, first_group_row, group_count, group_event_ids)
                written_all += 1

        # print(f"\n=== Output 1 Summary ===")
        # print(f"Total processed: {processed} lines")
        # print(f"Skipped (benign): {skipped_benign} lines")
        # print(f"Skipped (grouped duplicate): {skipped_duplicate} lines")
        # print(f"Written to {self.CSV_OUTPUT_ALL}: {written_all} lines (groups)")
        print(f"- Process 1 (all predictions with grouping): ")
        print(f"Written to {self.CSV_OUTPUT_ALL}: {written_all} lines (groups)")

        return written_all

    def _run_output2(self):
        """Output 2: Unique Datetime (with grouping)"""

        # Write to CSV - Version 2: Unique datetime with grouping
        # INPUT: Output 1 (not directly from result-4)
        total_lines_v2 = count_lines(self.CSV_OUTPUT_ALL)
        # print("\n" + "="*80)
        # print(f"OUTPUT 2: Unique Datetime (mode: {self.OUTPUT2_SELECTION_MODE})")
        # print("="*80)
        print(f"- Process 2 (unique datetime with grouping): ")
        # print(f"Input from Output 1: {total_lines_v2} lines")

        if self.OUTPUT2_SELECTION_MODE == "severity":
            print("Selection Logic: Get row with HIGHEST SEVERITY per datetime")
        elif self.OUTPUT2_SELECTION_MODE == "first":
            print("Selection Logic: Get FIRST row that appears per datetime")
        else:
            print(f"WARNING: Unknown mode '{self.OUTPUT2_SELECTION_MODE}', using 'first'")

        processed_v2 = 0
        written_unique = 0
        skipped_duplicate_datetime = 0

        # MODE: SEVERITY - Tracking datetime -> best row based on severity
        if self.OUTPUT2_SELECTION_MODE == "severity":
            datetime_best_rows = {}  # {datetime: {row_data, severity_score}}

            with open(self.CSV_OUTPUT_ALL, newline='', encoding="utf-8", errors='replace') as f:
                reader = csv.DictReader(f)

                for row in reader:
                    processed_v2 += 1

                    datetime_val = row.get('datetime', '')
                    severity = row.get('severity', '')
                    severity_score = get_severity_priority(severity)

                    # Check if datetime already exists
                    if datetime_val in datetime_best_rows:
                        # Compare severity
                        current_best_score = datetime_best_rows[datetime_val]['severity_score']

                        if severity_score > current_best_score:
                            # Higher severity, replace
                            datetime_best_rows[datetime_val] = {
                                'row': row,
                                'severity_score': severity_score
                            }
                            skipped_duplicate_datetime += 1
                        else:
                            # Lower or equal severity, skip
                            skipped_duplicate_datetime += 1
                    else:
                        # New datetime, save
                        datetime_best_rows[datetime_val] = {
                            'row': row,
                            'severity_score': severity_score
                        }

                    # Progress every 50,000 lines
                    if processed_v2 % 50000 == 0:
                        print(f"Processed {processed_v2}/{total_lines_v2} lines ({processed_v2/total_lines_v2:.2%})")

            # Write results to CSV (sorted by datetime)
            print("Writing results to CSV...")

            with open(self.CSV_OUTPUT_UNIQUE, "w", newline='', encoding="utf-8") as out:
                writer = csv.writer(out)

                # Header
                writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'label_predict', 'severity', 'group_count', 'low_event_ids'])

                # Sort by datetime and write
                sorted_datetimes = sorted(datetime_best_rows.keys())

                for datetime_val in sorted_datetimes:
                    row = datetime_best_rows[datetime_val]['row']

                    writer.writerow([
                        row.get('event_id', ''),
                        row.get('datetime', ''),
                        row.get('display_name', ''),
                        row.get('decoded', ''),
                        row.get('label_predict', ''),
                        row.get('severity', ''),
                        row.get('group_count', ''),
                        row.get('low_event_ids', '')
                    ])
                    written_unique += 1

            # print(f"\n=== Output 2 Summary (Severity Mode) ===")
            # print(f"- Summary :")
            # print(f"Total processed: {processed_v2} lines")
            # print(f"Skipped (duplicate datetime, lower/equal severity): {skipped_duplicate_datetime} lines")
            # print(f"Written to {self.CSV_OUTPUT_UNIQUE}: {written_unique} lines (groups)")
            print(f"Unique datetimes: {len(datetime_best_rows)}")

        # MODE: FIRST - Get first row per datetime
        else:
            seen_datetimes = set()

            with open(self.CSV_OUTPUT_ALL, newline='', encoding="utf-8", errors='replace') as f, \
                 open(self.CSV_OUTPUT_UNIQUE, "w", newline='', encoding="utf-8") as out:

                reader = csv.DictReader(f)
                writer = csv.writer(out)

                # Header
                writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'label_predict', 'severity', 'group_count', 'low_event_ids'])

                for row in reader:
                    processed_v2 += 1

                    datetime_val = row.get('datetime', '')

                    # Skip if datetime already exists
                    if datetime_val in seen_datetimes:
                        skipped_duplicate_datetime += 1
                        continue

                    # Write the first row for this datetime
                    writer.writerow([
                        row.get('event_id', ''),
                        row.get('datetime', ''),
                        row.get('display_name', ''),
                        row.get('decoded', ''),
                        row.get('label_predict', ''),
                        row.get('severity', ''),
                        row.get('group_count', ''),
                        row.get('low_event_ids', '')
                    ])
                    written_unique += 1

                    # Update tracking
                    seen_datetimes.add(datetime_val)

                    # Progress every 50,000 lines
                    if processed_v2 % 50000 == 0:
                        print(f"Processed {processed_v2}/{total_lines_v2} lines ({processed_v2/total_lines_v2:.2%})")

            print(f"\n=== Output 2 Summary (First Mode) ===")
            print(f"Total processed: {processed_v2} lines")
            print(f"Skipped (duplicate datetime): {skipped_duplicate_datetime} lines")
            print(f"Written to {self.CSV_OUTPUT_UNIQUE}: {written_unique} lines (groups)")
            print(f"Unique datetimes: {len(seen_datetimes)}")

        return written_unique

    def _print_summary(self, written_all, written_unique):
        # print("="*80)
        print("- Final summary:")
        # print("="*80)
        print(f"Output 1 (All Predictions):             {written_all:,} groups")
        print(f"Output 2 (Unique Datetime):             {written_unique:,} groups")
        # print("="*80)
