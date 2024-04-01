import os
import subprocess

def scan_directory_with_cve_bin_tool(directory, output_file):
    excluded_extensions = {".zip", ".html"}

    try:
        # Validate if the directory exists
        if not os.path.exists(directory):
            print(f"Directory '{directory}' does not exist.")
            return

        # Recursively walk through all subdirectories and files
        with open(output_file, "w") as output:
            for root, _, files in os.walk(directory):
                for filename in files:
                    filepath = os.path.join(root, filename)
                    if os.path.isfile(filepath):
                        # Check if the file extension is in the excluded list
                        _, file_extension = os.path.splitext(filename)
                        if file_extension.lower() in excluded_extensions:
                            print(f"Skipping excluded file: {filename}")
                            continue
                        print(f"Scanning file: {filepath}")
                        process = subprocess.Popen(["cve-bin-tool", filepath], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                        stdout, _ = process.communicate()

                        # Filter lines containing severity levels and file name
                        filtered_lines = [line for line in stdout.splitlines() if any(severity in line.lower() for severity in ["critical", "high", "medium", "low", "unknown"])]
                        if filtered_lines:
                            output.write(f"File: {filename}\n")
                            output.write("\n".join(filtered_lines) + "\n")
                            output.write("\n")

        print(f"Scan results saved to {output_file}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    user_directory = input("Enter the directory path to scan: ")
    user_output_file = input("Enter the output file name (e.g., results.txt): ")
    scan_directory_with_cve_bin_tool(user_directory, user_output_file)
