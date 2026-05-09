import sys
from normalization import Normalization
from log_decoder import LogDecoder
from low_level_predict import LowLevelPredict
from high_level_predict import HighLevelPredict
from low_level_gt import LowLevelGT
from low_level_evaluation import LowLevelEvaluation
from high_level_gt import HighLevelGT
from high_level_evaluation import HighLevelEvaluation

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python main.py <dataset_name>")
        print("Example: python main.py 1sample")
        sys.exit(1)

    dataset = sys.argv[1]

    print("")
    print("="*80)
    print("=== EVENT RECONSTRUCTION PROCESS ===")
    print("="*80)

    print("=== Step 1: Normalization ===")
    Normalization(dataset).run()

    print("\n=== Step 2: Log Decoder ===")
    LogDecoder(dataset).run()

    print("\n=== Step 3: Low Level Predict ===")
    LowLevelPredict(dataset).run()

    print("\n=== Step 4: High Level Predict ===")
    HighLevelPredict(dataset).run()

    print("")
    print("="*80)
    print("=== EVALUATION PROCESS ===")
    print("="*80)

    print("\n=== Eval Step 1: Low Level Ground Truth ===")
    LowLevelGT(dataset).run()

    print("\n=== Eval Step 2: Low Level Evaluation ===")
    LowLevelEvaluation(dataset).run()

    print("\n=== Eval Step 3: High Level Ground Truth ===")
    HighLevelGT(dataset).run()

    print("\n=== Eval Step 4: High Level Evaluation ===")
    HighLevelEvaluation(dataset).run()

    print("")