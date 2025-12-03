import configparser
import os
from cairosvg import svg2png
from PIL import Image
import io

CONFIG_PATH = 'config.ini'
FAVICON_OUTPUT_PATH = 'www/images/icons/favicon.ico'

# Default theme values
DEFAULTS = {
    'accent_color': '#17a2b8',
}

SVG_TEMPLATE = '''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<svg
   width="1000"
   height="1000"
   viewBox="0 0 1000 1000"
   version="1.1"
   xml:space="preserve"
   style="clip-rule:evenodd;fill-rule:evenodd;stroke-linejoin:round;stroke-miterlimit:1.5"
   id="svg974"
   sodipodi:docname="meshtastic_logo.svg"
   inkscape:export-xdpi="300"
   inkscape:export-ydpi="300"
   inkscape:export-filename="meshtastic_logo.png"
   xmlns:inkscape="http://www.inkscape.org/namespaces/inkscape"
   xmlns:sodipodi="http://sodipodi.sourceforge.net/DTD/sodipodi-0.dtd"
   xmlns="http://www.w3.org/2000/svg"
   xmlns:svg="http://www.w3.org/2000/svg"
   xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
   xmlns:cc="http://creativecommons.org/ns#"
   xmlns:dc="http://purl.org/dc/elements/1.1/">
  <title id="title346">Meshtastic Logo</title>
  <defs id="defs978"></defs>
  <sodipodi:namedview
    id="namedview976"
    pagecolor="#ffffff"
    bordercolor="#666666"
    borderopacity="1.0"
    inkscape:showpageshadow="2"
    inkscape:pageopacity="0.0"
    inkscape:pagecheckerboard="0"
    inkscape:deskcolor="#d1d1d1"
    showgrid="false"
    inkscape:zoom="0.35784754"
    inkscape:cx="435.93984"
    inkscape:cy="611.99247"
    inkscape:current-layer="g1140" />
  <g id="g1140" inkscape:label="MESHTASTIC" transform="translate(142.51879,93.615291)">
    <rect
      style="clip-rule:evenodd;fill:{accent_color};fill-rule:evenodd;stroke-width:2.31962;stroke-linecap:round;stroke-linejoin:bevel;stroke-miterlimit:1.5;stroke-dasharray:9.27846, 9.27846"
      id="rect400"
      width="997.63165"
      height="1008.8096"
      x="-139.7243"
      y="-99.204262"
      inkscape:label="bg" />
    <g id="g353" transform="matrix(3.2755924,0,0,3.2755924,24.465246,203.41775)">
      <path d="M 7.4991582,107.52902 76.014438,6.7704175" style="fill:none;stroke:{stroke_color};stroke-width:14.4391px" id="m1" inkscape:label="M" />
      <path d="M 71.87505,107.19881 137.46054,11.01544 203.197,107.04682" style="fill:none;fill-opacity:1;stroke:{stroke_color};stroke-width:14.2234px" id="m2" inkscape:label="M" />
    </g>
  </g>
  <metadata id="metadata342"><rdf:RDF><cc:Work rdf:about=""><dc:title>Meshtastic Logo</dc:title><dc:subject><rdf:Bag><rdf:li>meshtastic</rdf:li><rdf:li>meshtastik</rdf:li><rdf:li>мештастик</rdf:li></rdf:Bag></dc:subject><cc:license rdf:resource="http://creativecommons.org/licenses/by/4.0/" /><dc:source>https://meshtastic.org</dc:source><dc:language>EN</dc:language></cc:Work><cc:License rdf:about="http://creativecommons.org/licenses/by/4.0/"><cc:permits rdf:resource="http://creativecommons.org/ns#Reproduction" /><cc:permits rdf:resource="http://creativecommons.org/ns#Distribution" /><cc:requires rdf:resource="http://creativecommons.org/ns#Notice" /><cc:requires rdf:resource="http://creativecommons.org/ns#Attribution" /><cc:permits rdf:resource="http://creativecommons.org/ns#DerivativeWorks" /></cc:License></rdf:RDF></metadata>
</svg>'''

SIZES = [16, 32, 48, 64]

def is_dark(hex_color):
    hex_color = hex_color.lstrip('#')
    r, g, b = tuple(int(hex_color[i:i+2], 16) for i in (0, 2, 4))
    brightness = 0.299 * r + 0.587 * g + 0.114 * b
    return brightness < 128


def main():
    config = configparser.ConfigParser()
    config.read(CONFIG_PATH)
    theme = dict(DEFAULTS)
    theme.update(config['theme'] if 'theme' in config else {})
    accent_color = theme['accent_color']

    # Favicon background override
    favicon_background_color = theme.get('favicon_background_color') or accent_color
    # Favicon logo (stroke) color override
    favicon_logo_color = theme.get('favicon_logo_color')

    if favicon_logo_color:
        stroke_color = favicon_logo_color
    else:
        stroke_color = '#FFFFFF' if is_dark(favicon_background_color) else '#000000'

    svg_content = SVG_TEMPLATE.format(accent_color=favicon_background_color, stroke_color=stroke_color)
    png_images = []

    for size in SIZES:
        png_bytes = svg2png(bytestring=svg_content.encode('utf-8'), output_width=size, output_height=size)
        img = Image.open(io.BytesIO(png_bytes)).convert('RGBA')
        png_images.append(img)

    # Save as multi-resolution .ico
    png_images[0].save(FAVICON_OUTPUT_PATH, format='ICO', sizes=[(s, s) for s in SIZES], append_images=png_images[1:])
    print(f"Generated {FAVICON_OUTPUT_PATH} with sizes: {SIZES}")

if __name__ == '__main__':
    main() 