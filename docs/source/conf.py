import os
import sys
from datetime import date

sys.path.insert(0, os.path.abspath("../.."))

import waton  # noqa: E402

project = "Waton"
author = "Waton Contributors"
copyright = f"{date.today().year}, Waton Contributors"

version = waton.__version__
release = waton.__version__

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
]

templates_path = ["_templates"]
exclude_patterns: list[str] = []
source_suffix = [".rst", ".md"]
master_doc = "index"
language = "en"

html_theme = "sphinx_book_theme"
html_title = f"Waton {version} Documentation"
html_static_path = ["_static"]
html_css_files = [
    "https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.2/css/all.min.css",
    "custom.css",
]

html_theme_options = {
    "repository_url": "https://github.com/kaivyy/waton",
    "use_repository_button": True,
    "show_toc_level": 2,
    "navbar_end": ["theme-switcher", "navbar-icon-links"],
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/kaivyy/waton",
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        }
    ],
}
