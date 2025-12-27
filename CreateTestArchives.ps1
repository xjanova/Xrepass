# Create Test Archives for ZipCrackerUI
# This script creates various encrypted archive formats for testing

$testDir = "D:\Code\ZipCrackerUI\TestArchives"
New-Item -ItemType Directory -Force -Path $testDir | Out-Null

# Create a test text file
$testFile = "$testDir\test.txt"
"This is a test file for password cracking." | Out-File -FilePath $testFile -Encoding UTF8

Write-Host "Creating test archives..." -ForegroundColor Cyan

# 1. PKZIP Traditional (ZipCrypto) - Password: "123"
Write-Host "1. Creating PKZIP Traditional (password: 123)..." -ForegroundColor Yellow
$zipTraditional = "$testDir\test_pkzip_123.zip"
if (Test-Path $zipTraditional) { Remove-Item $zipTraditional }
Compress-Archive -Path $testFile -DestinationPath $zipTraditional
# Note: PowerShell Compress-Archive doesn't support password encryption
# Manual step needed: Use 7-Zip or WinRAR to add password

# 2. WinZip AES - Password: "password"
Write-Host "2. Creating WinZip AES (password: password)..." -ForegroundColor Yellow
# Requires 7-Zip or WinZip command line

# 3. Numbers password - Password: "12345"
Write-Host "3. Creating test with numeric password (password: 12345)..." -ForegroundColor Yellow

# 4. Simple password - Password: "test"
Write-Host "4. Creating test with simple password (password: test)..." -ForegroundColor Yellow

Write-Host "`n=== Manual Steps Required ===" -ForegroundColor Red
Write-Host "PowerShell's Compress-Archive doesn't support password encryption."
Write-Host "Please use 7-Zip command line to create encrypted archives:" -ForegroundColor White
Write-Host ""
Write-Host "# PKZIP Traditional (ZipCrypto):" -ForegroundColor Green
Write-Host "7z a -tzip -p123 -mem=ZipCrypto `"$testDir\test_pkzip_123.zip`" `"$testFile`""
Write-Host ""
Write-Host "# WinZip AES-256:" -ForegroundColor Green
Write-Host "7z a -tzip -ppassword -mem=AES256 `"$testDir\test_aes256_password.zip`" `"$testFile`""
Write-Host ""
Write-Host "# Numeric password:" -ForegroundColor Green
Write-Host "7z a -tzip -p12345 -mem=ZipCrypto `"$testDir\test_numbers_12345.zip`" `"$testFile`""
Write-Host ""
Write-Host "# RAR5:" -ForegroundColor Green
Write-Host "WinRAR a -hp456 -ma5 `"$testDir\test_rar5_456.rar`" `"$testFile`""
Write-Host ""
Write-Host "# 7-Zip:" -ForegroundColor Green
Write-Host "7z a -t7z -p789 `"$testDir\test_7z_789.7z`" `"$testFile`""

# Create README
$readme = @"
# Test Archives for ZipCrackerUI

This directory contains test encrypted archives for validating hash extraction and cracking.

## Archive Files:

1. **test_pkzip_123.zip** (PKZIP Traditional / ZipCrypto)
   - Password: 123
   - Hashcat Mode: 17200-17230
   - Method: Hash string extraction

2. **test_aes256_password.zip** (WinZip AES-256)
   - Password: password
   - Hashcat Mode: 13600
   - Method: Direct file input

3. **test_numbers_12345.zip** (PKZIP Traditional)
   - Password: 12345
   - Hashcat Mode: 17200
   - Method: Hash string extraction

4. **test_rar5_456.rar** (RAR5)
   - Password: 456
   - Hashcat Mode: 13000
   - Method: Direct file input

5. **test_7z_789.7z** (7-Zip)
   - Password: 789
   - Hashcat Mode: 11600
   - Method: Direct file input

## Creating Archives Manually:

Use 7-Zip command line (install from https://www.7-zip.org/):

``````powershell
# PKZIP Traditional (ZipCrypto)
7z a -tzip -p123 -mem=ZipCrypto "test_pkzip_123.zip" "test.txt"

# WinZip AES-256
7z a -tzip -ppassword -mem=AES256 "test_aes256_password.zip" "test.txt"

# 7-Zip
7z a -t7z -p789 "test_7z_789.7z" "test.txt"
``````

## Hash Extraction Examples:

### PKZIP Traditional:
``````
$pkzip$1*1*2*0*e3*1c5*eda7a8de*0*28*8*e3*eda7*5096*a9fc73a3*$/pkzip$
``````

### WinZip AES:
Use the .zip file directly with Hashcat mode 13600

### RAR5:
Use the .rar file directly with Hashcat mode 13000

### 7-Zip:
Use the .7z file directly with Hashcat mode 11600

## Testing:

1. Load archive in ZipCrackerUI
2. Verify hash type detection
3. Test password cracking with known passwords
4. Validate both CPU and GPU modes
"@

$readme | Out-File -FilePath "$testDir\README.md" -Encoding UTF8

Write-Host "`nREADME.md created in $testDir" -ForegroundColor Green
Write-Host "`nTest file created: $testFile" -ForegroundColor Green
