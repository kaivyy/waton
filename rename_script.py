import os

EXCLUDE_DIRS = {".git", ".venv", "target", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules"}
EXTENSIONS = {".py", ".md", ".toml", ".rs", ".js", ".json", ".txt"}

REPLACEMENTS = {
    "pywa": "waton",
    "PYWA": "WATON",
    "PyWA": "Waton",
    "Pywa": "Waton"
}

def replace_in_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()
    except Exception:
        return
    
    new_content = content
    for old, new in REPLACEMENTS.items():
        new_content = new_content.replace(old, new)
    
    if new_content != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(new_content)
        print(f"Updated content: {path}")

# Also rename files if they have "pywa" in them
def rename_file(root, name):
    new_name = name
    for old, new in REPLACEMENTS.items():
        new_name = new_name.replace(old, new)
    
    if new_name != name:
        old_path = os.path.join(root, name)
        new_path = os.path.join(root, new_name)
        try:
            os.rename(old_path, new_path)
            print(f"Renamed file: {old_path} -> {new_path}")
            # Correctly handle the case where we rename a directory we're iterating through
            return new_path
        except Exception as e:
            print(f"Failed to rename {old_path}: {e}")
    return os.path.join(root, name)

# Rename the core 'pywa' folder first if it exists
if os.path.exists("pywa"):
    os.rename("pywa", "waton")
    print("Renamed root pywa folder to waton")

for root, dirs, files in os.walk("."):
    dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]
    
    for file in files:
        file_path = os.path.join(root, file)
        # Rename file first
        new_file_path = rename_file(root, file)
        
        if any(new_file_path.endswith(ext) for ext in EXTENSIONS):
            replace_in_file(new_file_path)

print("Done with aggressive rename.")
