import pandas as pd
import matplotlib.pyplot as plt
import io
import os

# 1. Load the data
# The script will look for the file in your specific path
file_path = 'benchmarks/benchmark_results.csv'

if not os.path.exists(file_path):
    print(f"Error: {file_path} not found. Please ensure the script is run in the Clean-Implementation folder.")
else:
    df = pd.read_csv(file_path)

    # Define the timing stages
    stages = ['setup_time', 'store_time', 'chalgen_time', 'proofgen_time', 'proofveri_time']

    # ---------------------------------------------------------
    # GRAPH 1: Total Time vs Challenge Size (Scaling for each File Size)
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 7))
    for fs in sorted(df['file_size'].unique()):
        subset = df[df['file_size'] == fs]
        plt.plot(subset['challenge_c'], subset['total'], label=f'{fs} bytes', marker='o')

    plt.xlabel('Challenge Size (c)')
    plt.ylabel('Total Execution Time (s)')
    plt.title('Total Performance vs Challenge Size')
    plt.legend(title="File Sizes", bbox_to_anchor=(1.05, 1), loc='upper left')
    plt.grid(True, which="both", ls="-", alpha=0.3)
    plt.tight_layout()
    plt.show()

    # ---------------------------------------------------------
    # GRAPH 2: Total Time vs File Size (Scaling for each Challenge Size)
    # ---------------------------------------------------------
    plt.figure(figsize=(12, 7))
    # Selecting representative challenge sizes for clarity
    target_challenges = [1, 10, 50, 200, 500, 1000]
    for c in target_challenges:
        if c in df['challenge_c'].unique():
            subset = df[df['challenge_c'] == c]
            plt.plot(subset['file_size'], subset['total'], label=f'c={c}', marker='s')

    plt.xscale('log') # Log scale is necessary for sizes from 512 to 1MB
    plt.xlabel('File Size (bytes, Log Scale)')
    plt.ylabel('Total Execution Time (s)')
    plt.title('Total Performance vs File Size')
    plt.legend(title="Challenge Sizes")
    plt.grid(True, which="both", ls="-", alpha=0.3)
    plt.tight_layout()
    plt.show()

    # ---------------------------------------------------------
    # GRAPH 3: Time Breakdown for 512B File (All Challenges)
    # ---------------------------------------------------------
    subset_512 = df[df['file_size'] == 512]
    if not subset_512.empty:
        subset_512.set_index('challenge_c')[stages].plot(kind='bar', stacked=True, figsize=(12, 7))
        plt.title('Time Breakdown for 512B File across Challenges')
        plt.ylabel('Time (seconds)')
        plt.xlabel('Challenge Size (c)')
        plt.legend(title='Stages', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()

    # ---------------------------------------------------------
    # GRAPH 4: Time Breakdown for Challenge Size 1 (All File Sizes)
    # ---------------------------------------------------------
    subset_c1 = df[df['challenge_c'] == 1]
    if not subset_c1.empty:
        subset_c1.set_index('file_size')[stages].plot(kind='bar', stacked=True, figsize=(12, 7))
        plt.title('Time Breakdown for Challenge Size 1 across File Sizes')
        plt.ylabel('Time (seconds)')
        plt.xlabel('File Size (bytes)')
        plt.legend(title='Stages', bbox_to_anchor=(1.05, 1), loc='upper left')
        plt.tight_layout()
        plt.show()