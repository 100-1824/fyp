#!/usr/bin/env python3
"""
Quick Model File Checker
Verifies that the Double DQN model files exist and are valid
"""

import os
from pathlib import Path

def check_model_files():
    """Check if model files exist and get their info"""
    print("="*70)
    print("DOUBLE DQN MODEL FILE CHECKER")
    print("="*70)

    model_dir = Path("/home/user/fyp/dids-dashboard/model")

    models_to_check = [
        "double_dqn_final.keras",
        "double_dqn_final_target.keras"
    ]

    print(f"\nChecking directory: {model_dir}\n")

    all_good = True
    for model_name in models_to_check:
        model_path = model_dir / model_name

        if model_path.exists():
            size_bytes = model_path.stat().st_size
            size_kb = size_bytes / 1024
            size_mb = size_kb / 1024

            print(f"✓ {model_name}")
            print(f"  Size: {size_bytes:,} bytes ({size_mb:.2f} MB)")
            print(f"  Path: {model_path}")
        else:
            print(f"✗ {model_name} - NOT FOUND")
            all_good = False
        print()

    if all_good:
        print("="*70)
        print("✓ All model files found successfully!")
        print("="*70)
        print("\nTo test the models, run:")
        print("  python rl_module/test_dqn_model.py --model dids-dashboard/model/double_dqn_final.keras")
    else:
        print("="*70)
        print("✗ Some model files are missing")
        print("="*70)

    # List all files in model directory
    print(f"\nAll files in {model_dir}:")
    print("-"*70)
    for item in sorted(model_dir.iterdir()):
        if item.is_file():
            size_mb = item.stat().st_size / (1024 * 1024)
            print(f"  {item.name:40s} {size_mb:8.2f} MB")

if __name__ == '__main__':
    check_model_files()
