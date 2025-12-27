Add-Type -AssemblyName System.Drawing

# Load the original image
$originalImage = [System.Drawing.Image]::FromFile("D:\Code\ZipCrackerUI\logo.png")

# Create multiple sizes for the icon (16, 32, 48, 256)
$sizes = @(16, 32, 48, 256)
$iconPath = "D:\Code\ZipCrackerUI\app.ico"

# Create a proper ICO file with multiple resolutions
$memStream = New-Object System.IO.MemoryStream

# ICO Header
$writer = New-Object System.IO.BinaryWriter($memStream)
$writer.Write([Int16]0)     # Reserved
$writer.Write([Int16]1)     # Type (1 = ICO)
$writer.Write([Int16]$sizes.Count) # Number of images

# Calculate data offset (header + directory entries)
$dataOffset = 6 + ($sizes.Count * 16)

# Store image data
$imageDataList = @()

foreach ($size in $sizes) {
    # Resize image
    $bitmap = New-Object System.Drawing.Bitmap($size, $size)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $graphics.DrawImage($originalImage, 0, 0, $size, $size)
    $graphics.Dispose()

    # Convert to PNG bytes
    $pngStream = New-Object System.IO.MemoryStream
    $bitmap.Save($pngStream, [System.Drawing.Imaging.ImageFormat]::Png)
    $pngBytes = $pngStream.ToArray()
    $pngStream.Dispose()
    $bitmap.Dispose()

    $imageDataList += ,@{
        Width = $size
        Height = $size
        Data = $pngBytes
        Offset = $dataOffset
    }

    $dataOffset += $pngBytes.Length
}

# Write directory entries
foreach ($imgData in $imageDataList) {
    $w = if ($imgData.Width -ge 256) { 0 } else { $imgData.Width }
    $h = if ($imgData.Height -ge 256) { 0 } else { $imgData.Height }

    $writer.Write([Byte]$w)           # Width
    $writer.Write([Byte]$h)           # Height
    $writer.Write([Byte]0)            # Color palette
    $writer.Write([Byte]0)            # Reserved
    $writer.Write([Int16]1)           # Color planes
    $writer.Write([Int16]32)          # Bits per pixel
    $writer.Write([Int32]$imgData.Data.Length)  # Size of image data
    $writer.Write([Int32]$imgData.Offset)       # Offset to image data
}

# Write image data
foreach ($imgData in $imageDataList) {
    $writer.Write($imgData.Data)
}

$writer.Flush()

# Save to file
$fileBytes = $memStream.ToArray()
[System.IO.File]::WriteAllBytes($iconPath, $fileBytes)

$writer.Dispose()
$memStream.Dispose()
$originalImage.Dispose()

Write-Host "Icon created successfully: app.ico with $($sizes.Count) sizes"
