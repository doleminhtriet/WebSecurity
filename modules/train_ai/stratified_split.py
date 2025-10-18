# scripts/stratified_split.py
import sys, pandas as pd
from sklearn.model_selection import train_test_split
from pathlib import Path

if len(sys.argv) != 4:
    print("Usage: python scripts/stratified_split.py <all.csv> <train.csv> <valid.csv>")
    raise SystemExit(1)

src, dst_train, dst_valid = sys.argv[1:]
df = pd.read_csv(src)
assert {'text','label'}.issubset(df.columns), "CSV must have columns: text,label"

train_df, valid_df = train_test_split(
    df, test_size=0.2, random_state=42, stratify=df['label']
)

Path(dst_train).parent.mkdir(parents=True, exist_ok=True)
train_df.to_csv(dst_train, index=False)
valid_df.to_csv(dst_valid, index=False)
print(f"Wrote {len(train_df)} → {dst_train}")
print(f"Wrote {len(valid_df)} → {dst_valid}")
