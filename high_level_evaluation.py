import pandas as pd
import os


# ===================================
# MAIN CLASS
# ===================================

class HighLevelEvaluation:

    def __init__(self, dataset):
        self.dataset = dataset
        self.GROUND_TRUTH_CSV = f"results/{dataset}/result-6-1-high-level-ground-truth-unique-datetime.csv"
        self.PREDICT_CSV = f"results/{dataset}/result-6-2-high-level-predict-unique-datetime.csv"
        self.OUTPUT_CSV = f"results/{dataset}/result-6-3-high-level-evaluation-datetime.csv"

    def run(self):
        os.makedirs(f"results/{self.dataset}", exist_ok=True)

        df_gt, df_pred = self._load_data()
        TP, FN, FP, precision, recall, f1_score, tp_datetime_set, fn_datetime_set, fp_datetime_set = self._calculate_confusion_matrix(df_gt, df_pred)
        df_final = self._export(df_gt, df_pred, tp_datetime_set, fp_datetime_set)
        self._print_summary(TP, FN, FP, precision, recall, f1_score, df_final)

    def _load_data(self):
        df_gt = pd.read_csv(self.GROUND_TRUTH_CSV)
        df_pred = pd.read_csv(self.PREDICT_CSV)

        print(f"Ground Truth: {len(df_gt)} rows")
        print(f"Ground Truth unique datetime: {df_gt['datetime'].nunique()}")
        # print()
        print(f"Predict: {len(df_pred)} rows")
        print(f"Predict unique datetime: {df_pred['datetime'].nunique()}")

        return df_gt, df_pred

    def _calculate_confusion_matrix(self, df_gt, df_pred):
        # Use SET for unique datetime
        gt_datetime_set = set(df_gt['datetime'])
        pred_datetime_set = set(df_pred['datetime'])

        # calculate TP, FN, FP
        tp_datetime_set = gt_datetime_set & pred_datetime_set
        fn_datetime_set = gt_datetime_set - pred_datetime_set
        fp_datetime_set = pred_datetime_set - gt_datetime_set

        TP = len(tp_datetime_set)
        FN = len(fn_datetime_set)
        FP = len(fp_datetime_set)

        # calculate metrics
        precision = TP / (TP + FP) if (TP + FP) > 0 else 0
        recall = TP / (TP + FN) if (TP + FN) > 0 else 0
        f1_score = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        # print("=" * 70)
        # print("- Confusion Matrix (Datetime Matching)")
        # print("=" * 70)
        # print(f"True Positive (TP):  {TP:5d}")
        # print(f"False Negative (FN): {FN:5d}")
        # print(f"False Positive (FP): {FP:5d}")
        # print()
        # print("- Metrics:")
        # print(f"Precision: {precision:.4f}")
        # print(f"Recall:    {recall:.4f}")
        # print(f"F1-Score:  {f1_score:.4f}")

        return TP, FN, FP, precision, recall, f1_score, tp_datetime_set, fn_datetime_set, fp_datetime_set

    def _export(self, df_gt, df_pred, tp_datetime_set, fp_datetime_set):
        # Start with GT rows
        df_export = df_gt.copy()

        # Initialize the prediction column with default values
        df_export['label_predict'] = '-'
        df_export['group_count'] = '-'
        df_export['low_event_ids'] = '-'
        df_export['status'] = 'FN'  # default

        # For TP, get info from df_pred that matches datetime
        for dt in tp_datetime_set:
            # Get GT rows with this datetime
            gt_mask = df_export['datetime'] == dt

            # Get Pred rows with this datetime
            pred_rows = df_pred[df_pred['datetime'] == dt]

            if len(pred_rows) > 0:
                # Get the first row from prediction (if there are multiple, get the first one)
                pred_row = pred_rows.iloc[0]

                # Set status TP
                df_export.loc[gt_mask, 'status'] = 'TP'

                # Fill prediction column
                df_export.loc[gt_mask, 'label_predict'] = pred_row['label_predict']
                df_export.loc[gt_mask, 'group_count'] = pred_row['group_count']
                df_export.loc[gt_mask, 'low_event_ids'] = pred_row['low_event_ids']

        # Add FP rows from Predict
        df_pred_fp = df_pred[df_pred['datetime'].isin(fp_datetime_set)].copy()
        df_pred_fp['ground_truth_label'] = '-'
        df_pred_fp['status'] = 'FP'

        # Ensure column order is consistent
        columns_order = ['event_id', 'datetime', 'display_name', 'decoded',
                         'ground_truth_label', 'label_predict', 'group_count',
                         'low_event_ids', 'status']

        df_export = df_export[columns_order]
        df_pred_fp = df_pred_fp[columns_order]

        # Combine GT dan FP
        df_final = pd.concat([df_export, df_pred_fp], ignore_index=True)

        # Sort by datetime
        df_final = df_final.sort_values('datetime').reset_index(drop=True)

        # Save
        df_final.to_csv(self.OUTPUT_CSV, index=False)

        # print(f"\nExport selesai! File disimpan di: {self.OUTPUT_CSV}")
        # print(f"Total {len(df_final)} rows diekspor.")
        # print()
        # print("Breakdown:")
        # print(df_final['status'].value_counts())

        return df_final

    def _print_summary(self, TP, FN, FP, precision, recall, f1_score, df_final):
        # print("\n" + "=" * 70)
        # print("- Summary")
        # print("=" * 70)
        # print(f"Dataset: {self.dataset}")
        # print()
        print("- Confusion Matrix:")
        print(f"  TP: {TP}")
        print(f"  FP: {FP}")
        print(f"  FN: {FN}")
        print()
        print("- Metrics:")
        print(f"  Precision: {precision:.4f}")
        print(f"  Recall:    {recall:.4f}")
        print(f"  F1-Score:  {f1_score:.4f}")
        print()
        print("- Output:")
        print(f"  File: {self.OUTPUT_CSV}")
        print(f"  Total rows: {len(df_final)}")
        # print("=" * 70)
