# This script checks in the current user's home directory, and finds any occurance of a subdirectory named regisrty.terraform.io EXCEPT for when one of it's containing directories includes "princeton" (case insensitive)
# It also removes older versions of providers where a directory contains multiple - only keeping the most recent.
#  An example of the above is in ~/code/wirebox/pennies/client-wirebox-pennies/Terraform/.terraform/providers/registry.opentofu.org/hashicorp/aws, which contains 5.84.0 and 6.3.0, so the 5.84.0 directory should be removed.
# The script only lists the directories which would be removed, and calculates the total space reclaimable for now.

import os
import re
from pathlib import Path
from collections import defaultdict
delete_unnecessary_providers = False  # Set to True to enable deletion
reclaimable_space = 0
home_dir = Path.home()
target_dir_name = "registry.terraform.io"
excluded_keyword = ""
directories_to_remove = []

def delete_directories(directories):
    if not delete_unnecessary_providers:
        print("Deletion is disabled. Set 'delete_unnecessary_providers' to True to enable.")
        return
        if delete_providers_in_old_projects:
            time_period_days = 182  # Default time period (can be updated by the user)
            cutoff_date = datetime.now() - timedelta(days=time_period_days)
            for directory in directories:
                try:
                    # Only process subdirectories of .terraform/providers
                    if ".terraform/providers" in str(directory):
                        # Check if the directory was created more than the specified time period ago
                        if datetime.fromtimestamp(directory.stat().st_ctime) < cutoff_date:
                            for item in directory.rglob('*'):
                                if item.is_file():
                                    item.unlink()  # Remove file
                                elif item.is_dir():
                                    item.rmdir()  # Remove empty directory
                            directory.rmdir()  # Remove the main directory
                            print(f"Deleted (old provider): {directory}")
                except Exception as e:
                    print(f"Failed to delete {directory}: {e}")
    for directory in directories:
        try:
            for item in directory.rglob('*'):
                if item.is_file():
                    item.unlink()  # Remove file
                elif item.is_dir():
                    item.rmdir()  # Remove empty directory
            directory.rmdir()  # Remove the main directory
            print(f"Deleted: {directory}")
        except Exception as e:
            print(f"Failed to delete {directory}: {e}")
def find_and_list_directories():
    global reclaimable_space
    for root, dirs, files in os.walk(home_dir):
        # Calculate the depth of the current directory
        depth = len(Path(root).relative_to(home_dir).parts)
        max_depth = 5  # Define max_depth to avoid undefined variable error
        if depth > max_depth:
            dirs[:] = []  # Prevent further traversal into deeper directories
            continue
        # Skip directories containing the excluded keyword (case insensitive)
        if excluded_keyword.lower() in root.lower():
            continue

        # Check if the target directory exists in the current path
        if target_dir_name in dirs:
            target_path = Path(root) / target_dir_name

            # Group directories by their parent path
            provider_versions = defaultdict(list)
            for subdir in target_path.rglob("*"):
                if subdir.is_dir():
                    # Extract version directories
                    version_match = re.search(r"(\d+\.\d+\.\d+)", subdir.name)
                    if version_match:
                        provider_versions[subdir.parent].append((subdir, version_match.group(1)))

            # Identify older versions to remove
            for _, versions in provider_versions.items():  # Replace unused 'parent' with '_'
                versions.sort(key=lambda x: list(map(int, x[1].split('.'))))  # Sort by version
                for old_version in versions[:-1]:  # Keep only the most recent version
                    directories_to_remove.append(old_version[0])
                    reclaimable_space += sum(f.stat().st_size for f in old_version[0].rglob('*') if f.is_file())

    # Output the results
    print("Directories to be removed:")
    for directory in directories_to_remove:
        print(directory)

    print(f"\nTotal reclaimable space: {reclaimable_space / (1024 * 1024):.2f} MB")

if __name__ == "__main__":
    find_and_list_directories()