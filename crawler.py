import os
from datetime import datetime
import pandas as pd
from features import calculate_entropy, score_file
import sys


def gather_files(root_dir):
    paths = []
    for root, dirs, files in os.walk(root_dir):
        for f in files:
            paths.append(os.path.join(root, f))
    return paths

# Use the folder passed as argument or current dir

target_dir = sys.argv[1] if len(sys.argv) > 1 else "."

file_paths = gather_files(target_dir)


file_infos = []
for fp in file_paths:
    try:
        stat = os.stat(fp)
        f = os.path.basename(fp)
        entropy = calculate_entropy(fp)
        file_info = {
            "path": fp,
            "name": f,
            "size": stat.st_size,
            "mtime": datetime.fromtimestamp(stat.st_mtime),
            "ctime": datetime.fromtimestamp(stat.st_ctime),
            "extension": os.path.splitext(f)[1].lower(),
            "entropy": entropy,
        }
        file_info["score"] = score_file(file_info)
        file_infos.append(file_info)
    except Exception as e:
        print(f"Error processing {fp}: {e}")

df = pd.DataFrame(file_infos)
top = df.sort_values("score", ascending=False).head(10)

print("\n[Top Suspicious Files]")
for _, row in top.iterrows():
    print(f"[{row['score']}] {row['path']} (Entropy: {row['entropy']})")