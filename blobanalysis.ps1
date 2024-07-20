Clear-Host

function Compute-Hash {
    param (
        [string]$filePath,
        [string]$algorithm
    )
    $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($algorithm)
    $fileStream = [System.IO.File]::OpenRead($filePath)
    $hashBytes = $hashAlgorithm.ComputeHash($fileStream)
    $fileStream.Close()
    return -join ($hashBytes | ForEach-Object { "{0:X2}" -f $_ })
}

function Extract-HeadersFromBlob {
    param (
        [string]$BlobPath,
        [string]$OutputDir
    )

    $headerSignatures = @{
        "PDF"   = [byte[]](0x25, 0x50, 0x44, 0x46)
        "ZIP"   = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
        "PNG"   = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
        "JPG"   = [byte[]]@(0xFF, 0xD8, 0xFF)
        "GIF"   = [byte[]]@(0x47, 0x49, 0x46, 0x38, 0x39, 0x61)
        "DOCX"  = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
        "EXE"   = [byte[]]@(0x4D, 0x5A)
        "ELF"   = [byte[]]@(0x7F, 0x45, 0x4C, 0x46)
        "RUST"  = [byte[]](0x2F, 0x2F, 0x21)  # Rust files often start with //!
    }

    $apiPatterns = @(
        "CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "CloseHandle",
        "VirtualAlloc", "VirtualFree", "WriteProcessMemory", "ReadProcessMemory",
        "CreateRemoteThread", "OpenProcess", "GetProcAddress", "LoadLibraryA",
        "LoadLibraryW", "GetModuleHandleA", "GetModuleHandleW", "GetLastError",
        "SetWindowsHookExA", "SetWindowsHookExW", "UnhookWindowsHookEx",
        "SendMessageA", "SendMessageW", "PostMessageA", "PostMessageW",
        "ConnectSocket", "Recv", "Send", "Socket", "WSASocketA", "WSASocketW",
        "WSARecv", "WSASend", "Bind", "Listen", "Accept", "Select", "Shutdown",
        "WSAStartup", "WSACleanup", "InternetOpenA", "InternetOpenW", "InternetConnectA",
        "InternetConnectW", "InternetReadFile", "InternetWriteFile", "InternetCloseHandle",
        "RegOpenKeyA", "RegOpenKeyW", "RegQueryValueA", "RegQueryValueW", "RegSetValueA",
        "RegSetValueW", "RegCreateKeyA", "RegCreateKeyW", "RegDeleteKeyA", "RegDeleteKeyW",
        "RegEnumKeyA", "RegEnumKeyW", "RegEnumValueA", "RegEnumValueW", "RegDeleteValueA",
        "RegDeleteValueW", "RegCloseKey", "RegConnectRegistryA", "RegConnectRegistryW",
        "NetUserAdd", "NetUserDel", "NetUserModalsGet", "NetUserGetInfo", "NetUserSetInfo"
    )

    if (-not (Test-Path $BlobPath)) {
        Write-Error "The specified blob path does not exist: $BlobPath"
        return
    }

    $desktopPath = [System.Environment]::GetFolderPath('Desktop')
    $fullOutputDir = Join-Path $desktopPath $OutputDir
    if (-not (Test-Path $fullOutputDir)) {
        Write-Output "Creating output directory: $fullOutputDir"
        New-Item -Path $fullOutputDir -ItemType Directory | Out-Null
    }

    try {
        $fileContent = [System.IO.File]::ReadAllBytes($BlobPath)
        Write-Output "################ Blob Analysis Initiated ##############"
        Write-Output "##############                             ############"
        Write-Output "################## CyberTeam Medicom ##################"
        Write-output "###################### Dmichos ########################"
        Write-Output "                                                       "
        Write-Output "Successfully read the blob file. Size: $($fileContent.Length) bytes."
        Write-Output "                                                    "
    } catch {
        Write-Error "Failed to read the blob file. Error: $_"
        return
    }

    $foundSignatures = @{}
    foreach ($type in $headerSignatures.Keys) {
        $signature = $headerSignatures[$type]
        $positions = @()
        for ($i = 0; $i -lt $fileContent.Length - $signature.Length; $i++) {
            $match = $true
            for ($j = 0; $j -lt $signature.Length; $j++) {
                if ($fileContent[$i + $j] -ne $signature[$j]) {
                    $match = $false
                    break
                }
            }
            if ($match) {
                $positions += $i
            }
        }
        if ($positions.Count -gt 0) {
            $foundSignatures[$type] = $positions
            if ($type -eq "EXE") {
                Write-Host "Header '$type' found in the blob file." -ForegroundColor Red
            } else {
                Write-Output "Header '$type' found in the blob file."
            }
        } else {
            Write-Host "Header '$type' not found in the blob file." -ForegroundColor Red
        }
    }

    if ($foundSignatures.Count -eq 0) {
        Write-Output "No headers found in the blob file."
        return
    }

    function Get-HexDump {
        param (
            [byte[]]$Content,
            [int]$StartOffset,
            [int]$Length,
            [byte[]]$Signature
        )

        $hexDump = ""
        for ($i = $StartOffset; $i -lt [Math]::Min($StartOffset + $Length, $Content.Length); $i += 16) {
            $hexLine = "{0:X8}: " -f $i
            $asciiLine = ""
            for ($j = 0; $j -lt 16; $j++) {
                if ($i + $j -lt $Content.Length) {
                    $byteValue = $Content[$i + $j]
                    $formattedByte = "{0:X2}" -f $byteValue
                    $hexLine += $formattedByte + " "
                    $asciiLine += if ($byteValue -ge 32 -and $byteValue -le 126) { [char]$byteValue } else { '.' }
                } else {
                    $hexLine += "   "
                }
            }
            $hexDump += "$hexLine $asciiLine`n"
        }
        return $hexDump
    }

    function Search-APIFunctions {
        param (
            [byte[]]$Content,
            [string[]]$Patterns
        )

        $foundPatterns = @{}
        foreach ($pattern in $Patterns) {
            $patternBytes = [System.Text.Encoding]::ASCII.GetBytes($pattern)
            $patternLength = $patternBytes.Length
            $positions = @()
            for ($i = 0; $i -lt $Content.Length - $patternLength; $i++) {
                $match = $true
                for ($j = 0; $j -lt $patternLength; $j++) {
                    if ($Content[$i + $j] -ne $patternBytes[$j]) {
                        $match = $false
                        break
                    }
                }
                if ($match) {
                    $positions += $i
                }
            }
            if ($positions.Count -gt 0) {
                $foundPatterns[$pattern] = $positions
            }
        }
        return $foundPatterns
    }
    Write-Output "                                                    "
    Write-Output "==> Reconstructing blob <=="

    $constructedStrings = @()
    for ($i = 0; $i -lt $fileContent.Length; $i++) {
        if ($fileContent[$i] -ge 32 -and $fileContent[$i] -le 126) {
            $str = ""
            while ($i -lt $fileContent.Length -and $fileContent[$i] -ge 32 -and $fileContent[$i] -le 126) {
                $str += [char]$fileContent[$i]
                $i++
            }
            if ($str.Length -gt 4) {
                $constructedStrings += $str
            }
        }
    }

    $constructedStringsFile = Join-Path $fullOutputDir "constructed_strings.txt"
    try {
        [System.IO.File]::WriteAllLines($constructedStringsFile, $constructedStrings)
        Write-Output "                                                    "
        Write-Output "Constructed strings saved to: $constructedStringsFile"
    } catch {
        Write-Error "Failed to save the constructed strings file. Error: $_"
    }

    $newBlobPath = Join-Path $fullOutputDir "new_blob.bin"
    try {
        [System.IO.File]::WriteAllBytes($newBlobPath, $fileContent)
        $newBlobSize = (Get-Item $newBlobPath).Length
        Write-Output "                                                    "
        Write-Output "New_blob to read: $newBlobPath (Size: $newBlobSize bytes)"
    } catch {
        Write-Error "Failed to create the new blob file. Error: $_"
        return
    }

    foreach ($type in $foundSignatures.Keys) {
        Write-Host "Found $($foundSignatures[$type].Count) instances of header: $type" -ForegroundColor Green
        foreach ($startPos in $foundSignatures[$type]) {
            Write-Host "Header '$type' found at offset: $startPos" -ForegroundColor Green

            $hexDump = Get-HexDump -Content $fileContent -StartOffset ([Math]::Max($startPos - 32, 0)) -Length 64 -Signature $headerSignatures[$type]
            Write-Host $hexDump

            $fileName = "${type}_${startPos}.bin"
            $filePath = Join-Path $fullOutputDir $fileName
            $endPos = [Math]::Min($startPos + 1024 * 1024, $fileContent.Length)

            try {
                [System.IO.File]::WriteAllBytes($filePath, $fileContent[$startPos..($endPos - 1)])
                Write-Output "Extracted $type file saved as: $filePath"

                $md5Hash = Compute-Hash -filePath $filePath -algorithm "MD5"
                $sha1Hash = Compute-Hash -filePath $filePath -algorithm "SHA1"
                Write-Host "MD5: $md5Hash" -ForegroundColor Green
                Write-Host "SHA1: $sha1Hash" -ForegroundColor Green
                
                if ($type -eq "EXE") {
                    $extractedContent = [System.IO.File]::ReadAllBytes($filePath)
                    $foundPatterns = Search-APIFunctions -Content $extractedContent -Patterns $apiPatterns
                    if ($foundPatterns.Count -gt 0) {
                        Write-Host "Found API patterns in ${fileName}:" -ForegroundColor Cyan
                        foreach ($pattern in $foundPatterns.Keys) {
                            Write-Host "API pattern '${pattern}' found at offsets: $($foundPatterns[$pattern] -join ', ')" -ForegroundColor Cyan
                            $constructedStrings += "API pattern '${pattern}' found at offsets: $($foundPatterns[$pattern] -join ', ')"
                        }
                    } else {
                        Write-Output "                                                    "
                        Write-Host "No API patterns found in ${fileName}." -ForegroundColor Red
                        Write-Output "                                                    "
                    }
                }
            } catch {
                Write-Error "Failed to save the extracted file. Error: $_"
            }
        }
    }
}

$blobPath = "C:\Users\test\Desktop\32685_7b7d79488a8fcf482dd03104b09b3624_00000000000000000000000000000000"
$outputDir = "ExtractedFiles"
Extract-HeadersFromBlob -BlobPath $blobPath -OutputDir $outputDir
Write-Output "                                                    "
Write-Output "############# Blob Analysis Finished #################"
