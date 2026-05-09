import csv
import re
import os
import pandas as pd


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


# ===================================
# MAIN CLASS
# ===================================

class HighLevelGT:

    def __init__(self, dataset):
        self.dataset = dataset
        self.CSV_INPUT = f"results/{dataset}/result-3-low-level-ground-truth.csv"
        self.CSV_OUTPUT_ALL = f"results/{dataset}/result-6-1-high-level-ground-truth.csv"
        self.CSV_OUTPUT_UNIQUE = f"results/{dataset}/result-6-1-high-level-ground-truth-unique-datetime.csv"

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        written_all = self._run_output1()
        written_unique = self._run_output2()

        self._print_summary(written_all, written_unique)

    def _run_output1(self):
        """Output 1: All GT (with sequential duplicate filter)"""

        # Write to CSV - Version 1: All GTs that match the filter
        total_lines = count_lines(self.CSV_INPUT)
        print(f"Total lines in {self.CSV_INPUT}: {total_lines}")
        # print("\n" + "="*80)
        print("- Output 1: All Ground Truth Events (with sequential duplicate filter)")
        # print("="*80)

        processed = 0
        written_all = 0
        skipped_benign = 0
        skipped_duplicate = 0
        last_ground_truth_label = None  # Track previous labels for sequential duplicate detection

        with open(self.CSV_INPUT, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT_ALL, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Header
            writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'ground_truth_label'])

            for row in reader:
                processed += 1

                # Ambil nilai kolom
                event_id = row.get('event_id', '')
                datetime_val = row.get('datetime', '')
                display_name = row.get('display_name', '')
                decoded = row.get('decoded', '')
                ground_truth_label = row.get('ground_truth_label', '')

                # 1. Skip if ground_truth_label is 'benign' (does not reset last_ground_truth_label)
                if ground_truth_label.lower() == 'benign':
                    skipped_benign += 1
                    continue

                # 2. Skip if ground_truth_label is the same as the previous one (sequential duplicate)
                if ground_truth_label == last_ground_truth_label:
                    skipped_duplicate += 1
                    continue

                # Write row that passes the filter
                writer.writerow([event_id, datetime_val, display_name, decoded, ground_truth_label])
                written_all += 1

                # Update last label
                last_ground_truth_label = ground_truth_label

                # Progress every 50,000 lines
                if processed % 50000 == 0:
                    print(f"Processed {processed}/{total_lines} lines ({processed/total_lines:.2%})")

        # print(f"\n=== Output 1 Summary ===")
        print(f"Total processed: {processed} lines")
        print(f"Skipped (benign): {skipped_benign} lines")
        print(f"Skipped (duplicate label): {skipped_duplicate} lines")
        print(f"Written to {self.CSV_OUTPUT_ALL}: {written_all} lines")

        return written_all

    def _run_output2(self):
        """Output 2: Unique Datetime (take the first event per datetime)"""

        # Write to CSV - Version 2: Unique datetime (take the first event per datetime)
        # INPUT: Output 1 (not directly from result-3)
        total_lines_v2 = count_lines(self.CSV_OUTPUT_ALL)
        # print("\n" + "="*80)
        print("- Output 2: Unique Datetime (take the first event per datetime)")
        # print("="*80)
        print(f"Input from Output 1: {total_lines_v2} lines")

        processed_v2 = 0
        written_unique = 0
        skipped_duplicate_datetime = 0
        seen_datetimes = set()  # Track the datetime that has been written

        with open(self.CSV_OUTPUT_ALL, newline='', encoding="utf-8", errors='replace') as f, \
             open(self.CSV_OUTPUT_UNIQUE, "w", newline='', encoding="utf-8") as out:

            reader = csv.DictReader(f)
            writer = csv.writer(out)

            # Header
            writer.writerow(['event_id', 'datetime', 'display_name', 'decoded', 'ground_truth_label'])

            for row in reader:
                processed_v2 += 1

                # Get column value
                event_id = row.get('event_id', '')
                datetime_val = row.get('datetime', '')
                display_name = row.get('display_name', '')
                decoded = row.get('decoded', '')
                ground_truth_label = row.get('ground_truth_label', '')

                # Skip if datetime has already been written
                if datetime_val in seen_datetimes:
                    skipped_duplicate_datetime += 1
                    continue

                # Write row that passes the filter
                writer.writerow([event_id, datetime_val, display_name, decoded, ground_truth_label])
                written_unique += 1

                # Update tracking
                seen_datetimes.add(datetime_val)

                # Progress every 50,000 lines
                if processed_v2 % 50000 == 0:
                    print(f"Processed {processed_v2}/{total_lines_v2} lines ({processed_v2/total_lines_v2:.2%})")

        # print(f"\n=== Output 2 Summary ===")
        print(f"Total processed: {processed_v2} lines")
        print(f"Skipped (duplicate datetime): {skipped_duplicate_datetime} lines")
        print(f"Written to {self.CSV_OUTPUT_UNIQUE}: {written_unique} lines")

        return written_unique

    def _print_summary(self, written_all, written_unique):
        # print("\n" + "="*80)
        print("- Final summary:")
        # print("="*80)
        print(f"Output 1 (All GT):                      {written_all} events")
        print(f"Output 2 (Unique Datetime):             {written_unique} events")
        # print("="*80)
