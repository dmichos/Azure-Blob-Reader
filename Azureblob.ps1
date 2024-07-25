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
        "ZIP"   = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
        "PNG"   = [byte[]]@(0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A)
        "JPG"   = [byte[]]@(0xFF, 0xD8, 0xFF)
        "GIF"   = [byte[]]@(0x47, 0x49, 0x46, 0x38, 0x39, 0x61)
        "DOCX"  = [byte[]]@(0x50, 0x4B, 0x03, 0x04)
        "EXE"   = [byte[]]@(0x4D, 0x5A)
        "ELF"   = [byte[]]@(0x7F, 0x45, 0x4C, 0x46)
        "RUST"  = [byte[]](0x2F, 0x2F, 0x21)  
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
        Write-Output ""
        Write-Host "################ Azure Blob Analysis Initiated ##############" -ForegroundColor Cyan
        Write-Host "##############                             ############" -ForegroundColor Cyan
        Write-Host "##################                   ##################" -ForegroundColor Cyan
        Write-Host "###################### Dmichos ########################" -ForegroundColor Cyan
        Write-host  "      Artifacts Extractor Phase 1 Initiated              "  -ForegroundColor RED
        Write-host  ""
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
            Write-host "Header '$type' found in the blob file." -ForegroundColor Green
        }
    }

    if ($foundSignatures.Count -eq 0) {
        Write-host "No headers found in the blob file." -ForegroundColor Red
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
            $hexDump += "${hexLine} ${asciiLine}`n"
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

    Write-Output "                              "
    Write-host "==>> Reconstructing blob <===" -ForegroundColor RED

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
        Write-Output ""
        Write-Output "Constructed strings saved to: $constructedStringsFile"
    } catch {
        Write-Error "Failed to save the constructed strings file. Error: $_"
    }

    $newBlobPath = Join-Path $fullOutputDir "new_blob.bin"
    try {
        [System.IO.File]::WriteAllBytes($newBlobPath, $fileContent)
        $newBlobSize = (Get-Item $newBlobPath).Length
        Write-Output "                              "
        Write-Output "New_blob to read: $newBlobPath (Size: $newBlobSize bytes)"
        Write-Output ""
    } catch {
        Write-Error "Failed to create the new blob file. Error: $_"
        return
    }

    foreach ($type in $foundSignatures.Keys) {
        Write-Host "Found $($foundSignatures[$type].Count) instances of header: $type" -ForegroundColor Green
        foreach ($startPos in $foundSignatures[$type]) {
            Write-Output "                              "
            Write-Host "Header '$type' found at offset: $startPos" -ForegroundColor Green

            $hexDump = Get-HexDump -Content $fileContent -StartOffset ([Math]::Max($startPos - 32, 0)) -Length 64 -Signature $headerSignatures[$type]
            Write-Host $hexDump -ForegroundColor cyan

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
                        Write-Output "                              "
                        Write-Host "Found API patterns in ${fileName}:" -ForegroundColor Cyan
                        foreach ($pattern in $foundPatterns.Keys) {
                            Write-Host "API pattern '${pattern}' found at offsets: $($foundPatterns[$pattern] -join ', ')" -ForegroundColor Cyan
                            $constructedStrings += "API pattern '${pattern}' found at offsets: $($foundPatterns[$pattern] -join ', ')"
                        }
                    } else {
                        Write-Output "                              "
                        Write-Host "No API patterns found in ${fileName}." -ForegroundColor Red
                    }
                }
            } catch {
                Write-Error "Failed to save the extracted file. Error: $_"
            }
        }
    }

    Write-Host ""
    Write-Host "##########################################################" -ForegroundColor cyan
    Write-Host "            Indicators of Compromise (IOCs)              " -ForegroundColor Green
    Write-Host "       UUIDS - Emails - IPs - Domains - URLS             " -ForegroundColor Green
    Write-Host "  IOCS Files will be created with Kql query For Defender " -ForegroundColor Red
    Write-Host "##########################################################" -ForegroundColor  cyan
    Write-Host "             IOC Extractor Phase 2 Initiated             " -ForegroundColor Red
    Write-Host "##########################################################" -ForegroundColor  cyan
    Write-Host ""

    $indicators = Extract-IndicatorsFromBinaryFile -FilePath $newBlobPath
 
    Write-Host ""
    Write-Host "UUIDs Found:" -ForegroundColor Red
    $indicators.UUIDs | ForEach-Object { Write-Host $_ -ForegroundColor Green }
    $UUIDsFilePath = Join-Path $fullOutputDir "UUIDs_SearchPattern.txt"
    Create-DefenderSearchFile -FileName $UUIDsFilePath -Indicators $indicators.UUIDs -Type "UUIDs"
    Write-Host "[!] Defender Kql Query Created: $UUIDsFilePath" -ForegroundColor Cyan

 
    Write-Host ""
    Write-Host "Emails Found:" -ForegroundColor Red
    $indicators.Emails | ForEach-Object { Write-Host $_ -ForegroundColor Green }
    $EmailsFilePath = Join-Path $fullOutputDir "Emails_SearchPattern.txt"
    Create-DefenderSearchFile -FileName $EmailsFilePath -Indicators $indicators.Emails -Type "Emails"
    Write-Host "[!] Defender Kql Query Created: $EmailsFilePath" -ForegroundColor Cyan

 
    Write-Host ""
    Write-Host "IPs Found:" -ForegroundColor Red
    $indicators.IPs | ForEach-Object { Write-Host $_ -ForegroundColor Green }
    $IPsFilePath = Join-Path $fullOutputDir "IPs_SearchPattern.txt"
    Create-DefenderSearchFile -FileName $IPsFilePath -Indicators $indicators.IPs -Type "IPs"
    Write-Host "[!] Defender Kql Query Created: $IPsFilePath" -ForegroundColor Cyan

 
    Write-Host ""
    Write-Host "Domains Found:" -ForegroundColor Red
    $indicators.Domains | ForEach-Object { Write-Host $_ -ForegroundColor Green }
    $DomainsFilePath = Join-Path $fullOutputDir "Domains_SearchPattern.txt"
    Create-DefenderSearchFile -FileName $DomainsFilePath -Indicators $indicators.Domains -Type "Domains"
    Write-Host "[!] Defender Kql Query Created: $DomainsFilePath" -ForegroundColor Cyan

}

function Format-HexDump {
    param (
        [byte[]]$Data,
        [int]$Offset = 0,
        [int]$Width = 16,
        [int]$MaxLines = [int]::MaxValue,  
        [string]$Color = "White" 
    )

    $lineCount = 0

    for ($i = 0; $i -lt $Data.Length; $i += $Width) {
        if ($lineCount -ge $MaxLines) { break }

        $hex = ""
        $ascii = ""
        for ($j = 0; $j -lt $Width; $j++) {
            if ($i + $j -lt $Data.Length) {
                $byte = $Data[$i + $j]
                $hex += "{0:X2} " -f $byte
                if ($byte -ge 32 -and $byte -le 126) {
                    $ascii += [char]$byte
                } else {
                    $ascii += "."
                }
            } else {
                $hex += "   "
            }
        }
        $address = "{0:X8}" -f ($Offset + $i)
        Write-Host "${address}: $hex $ascii" -ForegroundColor $Color
        
        $lineCount++
    }
}

function Extract-PDFStreams {
    param (
        [string]$BlobPath,
        [string]$OutputDir
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
        Write-Output ""
    } catch {
        Write-Error "Failed to read the blob file. Error: $_"
        return
    }

    $pdfStartPattern = [System.Text.Encoding]::ASCII.GetBytes("obj<<")
    $pdfEndPattern1 = [System.Text.Encoding]::ASCII.GetBytes("endstream")
    $pdfEndPattern2 = [System.Text.Encoding]::ASCII.GetBytes("io.compression.gzipstre")

    $startPositions = @()
    $endPositions = @()

    for ($i = 0; $i -lt ($fileContent.Length - $pdfStartPattern.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $pdfStartPattern.Length; $j++) {
            if ($fileContent[$i + $j] -ne $pdfStartPattern[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $startPositions += $i
        }
    }

    for ($i = 0; $i -lt ($fileContent.Length - $pdfEndPattern1.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $pdfEndPattern1.Length; $j++) {
            if ($fileContent[$i + $j] -ne $pdfEndPattern1[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $endPositions += $i + $pdfEndPattern1.Length
        }
    }

    for ($i = 0; $i -lt ($fileContent.Length - $pdfEndPattern2.Length); $i++) {
        $match = $true
        for ($j = 0; $j -lt $pdfEndPattern2.Length; $j++) {
            if ($fileContent[$i + $j] -ne $pdfEndPattern2[$j]) {
                $match = $false
                break
            }
        }
        if ($match) {
            $endPositions += $i + $pdfEndPattern2.Length
        }
    }

    if ($startPositions.Count -gt 0 -and $endPositions.Count -gt 0) {
        Write-Output "                              " 
        Write-host " ############# PDF ####################" -ForegroundColor Cyan
        Write-Output "                              "
        Write-Host "PDF STREAM Found $($startPositions.Count) start patterns and $($endPositions.Count) end patterns." -ForegroundColor Green
    } else {
        Write-Output "                              "
        Write-Host "Found $($startPositions.Count) start patterns and $($endPositions.Count) end patterns." -ForegroundColor Red
    }

    for ($j = 0; $j -lt $startPositions.Count; $j++) {
        $start = $startPositions[$j]
        $end = if ($j -lt $endPositions.Count) { $endPositions[$j] } else { $null }

        if ($end) {
            Write-Output ""
            Write-Host "PDF stream found from offset $start to $end" -ForegroundColor Green

            $length = $end - $start
            $pdfStream = $fileContent[$start..($end - 1)]
            $streamFileName = "PDFStream_${j}.pdf"
            $streamFilePath = Join-Path $fullOutputDir $streamFileName
            [System.IO.File]::WriteAllBytes($streamFilePath, $pdfStream)
            Write-Output ""
            Write-Output "Extracted PDF stream saved to: $streamFilePath"
            Write-Output ""
            Write-Host "Hex dump of the extracted PDF stream:" -ForegroundColor Green

            Format-HexDump -Data $pdfStream -Offset $start -MaxLines 7 -Color "Red"

        } else {
            Write-Host "PDF start found at offset $start but no corresponding end pattern found." -ForegroundColor Red
        }
    }
}

function Validate-Domain {
    param (
        [string]$Domain
    )

    try {
        $dnsResult = Resolve-DnsName -Name $Domain -ErrorAction SilentlyContinue
        if ($dnsResult) {
            return $true
        } else {
            return $false
        }
    } catch {
        Write-Output "Error validating domain ${Domain}: $($_.Exception.Message)"
        return $false
    }
}

function Extract-IndicatorsFromBinaryFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath
    )

   
    function Reconstruct-Strings {
        param (
            [byte[]]$BinaryData
        )

        $stringBuilder = New-Object -TypeName System.Text.StringBuilder
        $reconstructedStrings = @()

        foreach ($byte in $BinaryData) {
            if ($byte -ge 32 -and $byte -le 126) {
                [void]$stringBuilder.Append([char]$byte)
            } else {
                if ($stringBuilder.Length -gt 4) {
                    $reconstructedStrings += $stringBuilder.ToString()
                }
                $stringBuilder.Clear() | Out-Null
            }
        }

        if ($stringBuilder.Length -gt 4) {
            $reconstructedStrings += $stringBuilder.ToString()
        }

        return $reconstructedStrings
    }

    
    $binaryData = [System.IO.File]::ReadAllBytes($FilePath)
    $reconstructedStrings = Reconstruct-Strings -BinaryData $binaryData

  
    $binaryString = $reconstructedStrings -join " "

  
    $uuidPattern = '[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}'
    $emailPattern = '\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    $ipPattern = '\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
    $domainPattern = '\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
    $urlPattern = '\bhttps?://[^\s/$.?#].[^\s]*\b'
    $filePathPattern = '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}/[^\s/$.?#].[^\s]*\b'

   
    $uuids = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $uuidPattern) | ForEach-Object { $_.Value }
    $emails = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $emailPattern) | ForEach-Object { $_.Value }
    $ips = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $ipPattern) | ForEach-Object { $_.Value }
    $domains = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $domainPattern) | ForEach-Object { $_.Value }
    $urls = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $urlPattern) | ForEach-Object { $_.Value }
    $filePaths = [System.Text.RegularExpressions.Regex]::Matches($binaryString, $filePathPattern) | ForEach-Object { $_.Value }

   
    $allUrls = $urls + $filePaths

   
    Write-Output "Debug - Raw Domains Found:"
    $domains | ForEach-Object { Write-Output $_ }

   
    $validDomains = @()
    foreach ($domain in $domains) {
        if (Validate-Domain -Domain $domain) {
            $validDomains += $domain
        }
    }

  
    Write-Output "Debug - Valid Domains Found:"
    $validDomains | ForEach-Object { Write-Output $_ }

    return @{
        UUIDs = $uuids
        Emails = $emails
        IPs = $ips
        Domains = $validDomains
        URLs = $allUrls
    }
}

function Create-DefenderSearchFile {
    param (
        [string]$FileName,
        [string[]]$Indicators,
        [string]$Type
    )

    $searchPattern = "DeviceNetworkEvents`n"

    if ($Type -eq "UUIDs" -or $Type -eq "Emails" -or $Type -eq "IPs") {
        
        $searchPattern += "| search "
        foreach ($indicator in $Indicators) {
            $searchPattern += "`"$indicator`" or`n        "
        }
        $searchPattern = $searchPattern.TrimEnd(" or`n        ")
    } elseif ($Type -eq "Domains" -or $Type -eq "URLs") {
       
        $searchPattern += "| where (RemoteUrl == "
        foreach ($indicator in $Indicators) {
            $searchPattern += "`"$indicator`" or`n        RemoteUrl == "
        }
        $searchPattern = $searchPattern.TrimEnd(" or`n        RemoteUrl == ")
        $searchPattern += ")"
    }

   
    Set-Content -Path $FileName -Value $searchPattern
}

$blobPath = "C:\Users\test\Desktop\i\32685_7b7d79488a8fcf482dd03104b09b3624_00000000000000000000000000000000"
$outputDir = "ExtractedFiles"

Extract-HeadersFromBlob -BlobPath $blobPath -OutputDir $outputDir
Extract-PDFStreams -BlobPath $blobPath -OutputDir $outputDir
Write-Output "                                           "
Write-Host "############# Blob Analysis Finished #################" -ForegroundColor Cyan
