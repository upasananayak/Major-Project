import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd

# Data for 20k embeddings including BERT
df_part4 = pd.DataFrame({
    'Model': ['20k_W2V', '20k_FT', '20k_GloVe', '20k_BERT', 'Base_200k_W2V'],
    'ROUGE-1': [0.3567, 0.3208, 0.3724, 0.3821, 0.429],
    'ROUGE-2': [0.1388, 0.1148, 0.1541, 0.1623, 0.197],
    'ROUGE-L': [0.2212, 0.1994, 0.2335, 0.2167, 0.393]
})

# Grouped Bar Plot
df_melt = df_part4.melt(id_vars='Model', var_name='Metric', value_name='Score')
plt.figure(figsize=(10, 5))
sns.barplot(data=df_melt, x='Model', y='Score', hue='Metric')
plt.title("20k BERT vs Static Embeddings and Base Paper: ROUGE Comparison")
plt.xticks(rotation=45, ha='right')
plt.tight_layout()
plt.show()

# Heatmap
plt.figure(figsize=(8, 4))
sns.heatmap(df_part4.set_index('Model'), annot=True, cmap='Greens', fmt=".3f")
plt.title("Heatmap: BERT vs Others on 20k Dataset")
plt.show()

