import pandas as pd
import matplotlib.pyplot as plt

# Load the datasets
file1 = r'benchmarks/benchmark_results_50.csv'  # Approach 1

df1 = pd.read_csv(file1)


# List of stages to compare
stages = ['setup_time', 'store_time', 'chalgen_time', 'proofgen_time', 'proofveri_time', 'total']

# Identify common file sizes for direct comparison
common_sizes = sorted(list(set(df1['file_size'].unique())))

def generate_comparison_plots(df1, sizes, stages):
    for size in sizes:
        # Filter data for the specific file size
        data1 = df1[df1['file_size'] == size].sort_values('challenge_c')
    
        
        # Create a grid of subplots (2 rows, 3 columns)
        fig, axes = plt.subplots(2, 3, figsize=(18, 10))
        fig.suptitle(f'Approach Comparison for File Size: {size}', fontsize=18, fontweight='bold')
        axes = axes.flatten()
        
        for i, stage in enumerate(stages):
            ax = axes[i]
            
            # Plot Approach 1 (benchmark_results_30.csv)
            if not data1.empty:
                ax.plot(data1['challenge_c'], data1[stage], marker='o', linestyle='-', 
                        linewidth=2, label='Approach 1 (results_50)')
            
          
            
            # Formatting the subplot
            ax.set_title(stage.replace('_', ' ').title(), fontsize=14)
            ax.set_xlabel('Number of Chunks (challenge_c)', fontsize=12)
            ax.set_ylabel('Time (seconds)', fontsize=12)
            ax.legend()
            ax.grid(True, which='both', linestyle='--', alpha=0.6)
            
        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        
        # Save the graph
        filename = f'comparison_plots_size_{size}.png'
        plt.savefig(filename)
        print(f"Generated plot: {filename}")
        plt.close()

        

# Run the function
generate_comparison_plots(df1,common_sizes, stages)