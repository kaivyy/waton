import os

EXCLUDE_DIRS = {".git", ".venv", "target", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules", ".claude", "docs"}
EXTENSIONS = {".py", ".md", ".toml", ".rs", ".js", ".json", ".txt"}

def replace_in_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return
    
    new_content = content.replace("waton", "waton").replace("WATON", "WATON").replace("Waton", "Waton")
    
    if new_content != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Updated: {path}")

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    
    for file in files:
        if any(file.endswith(ext) for ext in EXTENSIONS):
            replace_in_file(os.path.join(root, file))

print("Done replacing text.")
