# WordPress.org Plugin Assets

These SVG source files are used to generate the PNG assets required by the
WordPress.org plugin directory.

## Required PNG files (upload to SVN `assets/` directory)

| File                 | Source       | Size       |
|----------------------|-------------|------------|
| icon-128x128.png     | icon.svg    | 128 x 128  |
| icon-256x256.png     | icon.svg    | 256 x 256  |
| banner-772x250.png   | banner.svg  | 772 x 250  |
| banner-1544x500.png  | banner.svg  | 1544 x 500 |

## Convert with ImageMagick

```bash
convert -background none icon.svg -resize 128x128 icon-128x128.png
convert -background none icon.svg -resize 256x256 icon-256x256.png
convert banner.svg -resize 1544x500 banner-1544x500.png
convert banner.svg -resize 772x250 banner-772x250.png
```

## Convert with rsvg-convert (alternative)

```bash
rsvg-convert -w 128 -h 128 icon.svg > icon-128x128.png
rsvg-convert -w 256 -h 256 icon.svg > icon-256x256.png
rsvg-convert -w 1544 -h 500 banner.svg > banner-1544x500.png
rsvg-convert -w 772 -h 250 banner.svg > banner-772x250.png
```

## Notes

- The icon uses a shield with a web/honeycomb pattern in dark navy and green.
- The banner uses a dark gradient background with the plugin name and tagline.
- Upload the generated PNGs (not the SVGs) to the WordPress.org SVN `assets/`
  directory. SVG files are kept here as editable sources only.
