# generate_params.py
import json
from pq_utils import demo_group_params

params = demo_group_params()  # expensive; run once
with open("zk_params.json", "w") as f:
    json.dump({k: int(v) for k, v in params.items()}, f)
print("Wrote zk_params.json (store this securely and reuse).")
