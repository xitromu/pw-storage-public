param(
    [string]$Path = 'C:\projects\PW_STORAGE\assets\pw_storage_lock.png',
    [string]$Target = 'C:\projects\PW_STORAGE\assets\icons'
)
Add-Type -AssemblyName System.Drawing
if (-not (Test-Path $Target)) { New-Item -ItemType Directory -Path $Target | Out-Null }
$image = [System.Drawing.Image]::FromFile($Path)
foreach ($size in 256, 64, 48, 32, 16) {
    $bmp = New-Object System.Drawing.Bitmap ($size, $size)
    $gfx = [System.Drawing.Graphics]::FromImage($bmp)
    $gfx.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $gfx.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::HighQuality
    $gfx.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $gfx.DrawImage($image, 0, 0, $size, $size)
    $gfx.Dispose()
    $bmp.Save((Join-Path $Target ("{0}.png" -f $size)), [System.Drawing.Imaging.ImageFormat]::Png)
    $bmp.Dispose()
}
Write-Output ('source ' + $image.Width + 'x' + $image.Height)
$image.Dispose()
