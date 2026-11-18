from markupsafe import Markup, escape
def unsafe(title):
    # ruleid: unescaped-markup
    return Markup(title)
# ok: unescaped-markup
def safe(title):
    return escape(title)
