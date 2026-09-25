# Grabs a pixel-exact screenshot of the MTKey window for the README.
# usage: powershell -ExecutionPolicy Bypass -File tools/screenshot.ps1 <exe-path> <out-png>
param(
    [Parameter(Mandatory = $true)][string]$ExePath,
    [Parameter(Mandatory = $true)][string]$OutPng
)

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
Add-Type @"
using System;
using System.Runtime.InteropServices;
public struct RECT { public int Left; public int Top; public int Right; public int Bottom; }
public class Win32 {
    [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr hWnd, out RECT rect);
    [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr hWnd);
}
"@

# A staged session: AES-256-GCM with the NIST SP 800-38D test key and nonce,
# so the README shot shows the toolbar, parameter rows, dice and a live result.
$demoArgs = @(
    '--demo', '--method', 'aes-gcm',
    '--set', 'key=603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4',
    '--set', 'keyenc=Hex',
    '--set', 'iv=cafebabefacedbaddecaf888',
    '--set', 'ivenc=Hex',
    '"The quick brown fox jumps over the lazy dog"'
)

$proc = Start-Process -FilePath $ExePath -ArgumentList $demoArgs -PassThru
Start-Sleep -Milliseconds 4000

[Win32]::SetForegroundWindow($proc.MainWindowHandle) | Out-Null
Start-Sleep -Milliseconds 400

$rect = New-Object RECT
[Win32]::GetWindowRect($proc.MainWindowHandle, [ref]$rect) | Out-Null
$w = $rect.Right - $rect.Left
$h = $rect.Bottom - $rect.Top
Write-Output "window at $($rect.Left),$($rect.Top) size ${w}x${h}"

$bmp = New-Object System.Drawing.Bitmap($w, $h)
$gfx = [System.Drawing.Graphics]::FromImage($bmp)
$gfx.CopyFromScreen($rect.Left, $rect.Top, 0, 0, (New-Object System.Drawing.Size($w, $h)))
$bmp.Save($OutPng, [System.Drawing.Imaging.ImageFormat]::Png)
$gfx.Dispose(); $bmp.Dispose()

Stop-Process -Id $proc.Id -Force
Write-Output "saved $OutPng"
