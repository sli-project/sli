param(
    [string]$ProjectRoot = (Split-Path -Parent (Split-Path -Parent $PSScriptRoot)),
    [int]$DarkFloor = 25,
    [int]$OpaqueFrom = 105
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version 2.0

if ($DarkFloor -lt 0 -or $OpaqueFrom -le $DarkFloor -or $OpaqueFrom -gt 255) {
    throw "Expected 0 <= DarkFloor < OpaqueFrom <= 255."
}

Add-Type -AssemblyName System.Drawing

$SourceDirectory = Join-Path $ProjectRoot "web\app\assets\sli-login"
$OutputDirectory = Join-Path $ProjectRoot "web\app\assets\sli-login-clean"
$AssetNames = @(
    "map-streams.svg",
    "collector-server.svg",
    "node-warning.svg",
    "node-user.svg",
    "node-storage.svg",
    "node-lock.svg"
)
$FlattenedMapRegions = @(
    @{ Left = 0; Top = 0; Right = 415; Bottom = 240; Feather = 42.0 },
    @{ Left = 105; Top = 330; Right = 350; Bottom = 575; Feather = 48.0 },
    @{ Left = 490; Top = 75; Right = 625; Bottom = 220; Feather = 32.0 },
    @{ Left = 490; Top = 280; Right = 630; Bottom = 425; Feather = 32.0 },
    @{ Left = 530; Top = 420; Right = 680; Bottom = 570; Feather = 34.0 },
    @{ Left = 460; Top = 555; Right = 615; Bottom = 715; Feather = 34.0 }
)

New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null

foreach ($AssetName in $AssetNames) {
    $SourcePath = Join-Path $SourceDirectory $AssetName
    $OutputPath = Join-Path $OutputDirectory $AssetName
    $Svg = [IO.File]::ReadAllText($SourcePath, [Text.Encoding]::UTF8)
    $SizeMatch = [regex]::Match(
        $Svg,
        '<svg[^>]*width="(?<width>\d+)"[^>]*height="(?<height>\d+)"[^>]*viewBox="(?<viewBox>[^"]+)"'
    )
    $DataMatch = [regex]::Match($Svg, 'href="data:image/png;base64,(?<data>[^"]+)"')
    if (-not $SizeMatch.Success -or -not $DataMatch.Success) {
        throw "Unsupported SLI SVG container: $SourcePath"
    }

    $InputBytes = [Convert]::FromBase64String($DataMatch.Groups["data"].Value)
    $InputStream = [IO.MemoryStream]::new($InputBytes)
    try {
        $SourceBitmap = [Drawing.Bitmap]::new($InputStream)
        try {
            $OutputBitmap = [Drawing.Bitmap]::new(
                $SourceBitmap.Width,
                $SourceBitmap.Height,
                [Drawing.Imaging.PixelFormat]::Format32bppArgb
            )
            try {
                for ($Y = 0; $Y -lt $SourceBitmap.Height; $Y++) {
                    for ($X = 0; $X -lt $SourceBitmap.Width; $X++) {
                        $Color = $SourceBitmap.GetPixel($X, $Y)
                        if ($Color.A -eq 0) {
                            $OutputBitmap.SetPixel($X, $Y, $Color)
                            continue
                        }

                        $PixelFloor = $DarkFloor
                        $PixelOpaqueFrom = $OpaqueFrom
                        $FlattenedBackgroundStrength = 0.0
                        if ($AssetName -eq "map-streams.svg") {
                            foreach ($Region in $FlattenedMapRegions) {
                                $OutsideX = [Math]::Max(
                                    [Math]::Max($Region.Left - $X, 0.0),
                                    $X - $Region.Right
                                )
                                $OutsideY = [Math]::Max(
                                    [Math]::Max($Region.Top - $Y, 0.0),
                                    $Y - $Region.Bottom
                                )
                                $OutsideDistance = [Math]::Sqrt(
                                    ($OutsideX * $OutsideX) +
                                    ($OutsideY * $OutsideY)
                                )
                                if ($OutsideDistance -lt $Region.Feather) {
                                    $T = [Math]::Min(
                                        1.0,
                                        1.0 - ($OutsideDistance / $Region.Feather)
                                    )
                                    $Strength = $T * $T * (3.0 - 2.0 * $T)
                                    $FlattenedBackgroundStrength = [Math]::Max(
                                        $FlattenedBackgroundStrength,
                                        $Strength
                                    )
                                }
                            }
                        }
                        else {
                            $PixelFloor = [Math]::Max($PixelFloor, 145)
                            $PixelOpaqueFrom = [Math]::Max($PixelOpaqueFrom, 225)
                        }

                        $Brightness = [Math]::Max(
                            $Color.R,
                            [Math]::Max($Color.G, $Color.B)
                        )
                        if ($Brightness -le $PixelFloor) {
                            $Alpha = 0
                        }
                        elseif ($Brightness -ge $PixelOpaqueFrom) {
                            $Alpha = $Color.A
                        }
                        else {
                            $T = ($Brightness - $PixelFloor) / ($PixelOpaqueFrom - $PixelFloor)
                            $Smooth = $T * $T * (3.0 - 2.0 * $T)
                            $Alpha = [int][Math]::Round($Color.A * $Smooth)
                        }
                        if ($FlattenedBackgroundStrength -gt 0 -and $Brightness -lt 232) {
                            $Alpha = [int][Math]::Round(
                                $Alpha * (1.0 - $FlattenedBackgroundStrength)
                            )
                        }
                        $OutputBitmap.SetPixel(
                            $X,
                            $Y,
                            [Drawing.Color]::FromArgb($Alpha, $Color.R, $Color.G, $Color.B)
                        )
                    }
                }

                $OutputStream = [IO.MemoryStream]::new()
                try {
                    $OutputBitmap.Save($OutputStream, [Drawing.Imaging.ImageFormat]::Png)
                    $Encoded = [Convert]::ToBase64String($OutputStream.ToArray())
                }
                finally {
                    $OutputStream.Dispose()
                }
            }
            finally {
                $OutputBitmap.Dispose()
            }
        }
        finally {
            $SourceBitmap.Dispose()
        }
    }
    finally {
        $InputStream.Dispose()
    }

    $Width = $SizeMatch.Groups["width"].Value
    $Height = $SizeMatch.Groups["height"].Value
    $ViewBox = $SizeMatch.Groups["viewBox"].Value
    $Generated = '<svg xmlns="http://www.w3.org/2000/svg" width="{0}" height="{1}" viewBox="{2}"><image width="{0}" height="{1}" href="data:image/png;base64,{3}"/></svg>' -f $Width, $Height, $ViewBox, $Encoded
    [IO.File]::WriteAllText($OutputPath, $Generated, [Text.UTF8Encoding]::new($false))
    Write-Host "Generated $OutputPath"
}
