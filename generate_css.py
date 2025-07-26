import configparser
import os
import logging
from jinja2 import Template

CONFIG_PATH = 'config.ini'
TEMPLATE_PATH = 'www/css/meshinfo.css.template'
OUTPUT_PATH = 'www/css/meshinfo.css'

# Default theme values
DEFAULTS = {
    'header_color': '#9fdef9',
    'table_header_color': '#D7F9FF',
    'table_alternating_row_color': '#f0f0f0',
    'accent_color': '#17a2b8',
    'page_background_color': '#ffffff',
    'table_border_color': '#dee2e6',
    'link_color': '#007bff',
    'link_color_hover': '#0056b3',
    'control_color': '#17a2b8',
    'control_color_hover': '#1396a5',
    'header_link_color': '#555',
    'header_link_active_color': '#000',
    'header_brand_color': '#000',
    'chat_box_background_color': '#f8f9fa',
    'chat_box_border_color': '',
}

config = configparser.ConfigParser()
config.read(CONFIG_PATH)
theme = dict(DEFAULTS)
theme.update(config['theme'] if 'theme' in config else {})

# Generate CSS using Jinja2 template engine
with open(TEMPLATE_PATH) as f:
    template_content = f.read()

template = Template(template_content)
css = template.render(**theme)

with open(OUTPUT_PATH, 'w') as f:
    f.write(css)

logging.info(f"Generated {OUTPUT_PATH} from {TEMPLATE_PATH} using theme from {CONFIG_PATH}")