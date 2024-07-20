# Blob Analysis Script
## Overview
 This PowerShell script is designed to perform detailed analysis on binary blobs, specifically focusing on extracting file headers and searching for known API patterns within executables. The script is useful for security researchers and forensic analysts who need to dissect and examine binary data for various file signatures and potential malicious content.

## Features
 - Header Extraction: Identifies and extracts various file types based on their signatures, including PDF, ZIP, PNG, JPG, GIF, DOCX, EXE, ELF, and RUST files.
 - API Pattern Search: Searches for known API function calls within executable files, which can indicate potential malicious behavior.
 - Hash Computation: Computes and displays MD5 and SHA1 hashes for the extracted files.
 - Reconstructed Strings: Reconstructs and saves readable strings found within the blob, aiding in further analysis.

## Usage
- Setup: Ensure the blob file to be analyzed is accessible on your system.
- Run the Script: Execute the script in PowerShell, specifying the path to your blob file and the output directory for extracted files.
 -Review Results: Examine the extracted files, hashes, and API patterns identified by the script.

  ## Example
```

```
