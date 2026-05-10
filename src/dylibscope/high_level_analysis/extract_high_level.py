import lief
import json
import os


def extract_ios_deployment(binary):
    for cmd in binary.commands:
        if isinstance(cmd, lief.MachO.VersionMin):  # pre–iOS 12
            return ".".join(map(str, cmd.version))
        if isinstance(cmd, lief.MachO.BuildVersion):  # iOS 12+
            return ".".join(map(str, cmd.minos))
    return None


def analyze_dylib(path, ios_root_label):
    try:
        binary = lief.parse(path)
        if not isinstance(binary, lief.MachO.Binary):
            return None

        exported_functions = [s.name for s in binary.exported_symbols if s.name]
        imported_functions = [s.name for s in binary.imported_symbols if s.name]

        return {
            "file": os.path.basename(path),
            "deployment_target": extract_ios_deployment(binary),  
            "ios_version": ios_root_label,                       
            "path": path,
            "num_sections": len(binary.sections),
            "num_symbols": len(binary.symbols),
            "exported_functions": ";".join(exported_functions),
            "imported_functions": ";".join(imported_functions),
        }

    except Exception as e:
        print(f"[!] Failed to analyze {path}: {e}")
        return None


def analyze_directory(dir_path, recursive=False, return_data=False):
    entries = []

    ios_root_label = os.path.basename(os.path.normpath(dir_path))

    for root, _, files in os.walk(dir_path):
        for file in files:
            if file.endswith(".dylib"):
                full_path = os.path.join(root, file)
                data = analyze_dylib(full_path, ios_root_label)
                if data:
                    entries.append(data)
        if not recursive:
            break

    if return_data:
        return entries


def analyze_from_filelist(list_path, output_path="dylibs_analysis_local.json", recursive=True):
    count = 0

    with open(output_path, "w") as out_f:
        with open(list_path, "r") as f:
            for line in f:
                parent_path = line.strip()
                if not parent_path or parent_path.startswith("#"):
                    continue

                for entry in os.listdir(parent_path):
                    subdir = os.path.join(parent_path, entry)
                    if not os.path.isdir(subdir):
                        continue

                    ios_root_label = os.path.basename(subdir)
                    print(f"[→] Analyzing: {subdir} (iOS version: {ios_root_label})")

                    try:
                        results = analyze_directory(subdir, recursive=recursive, return_data=True)
                        for r in results:
                            out_f.write(json.dumps(r) + "\n")
                            count += 1
                    except Exception as e:
                        print(f"[!] Failed to analyze {subdir}: {e}")

    print(f"\n[✓] Analysis complete. {count} total libraries processed.")


def main():
    analyze_from_filelist("dylib_list.txt")


if __name__ == '__main__':
    main()
