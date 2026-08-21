import re
# 1. Update index.html
content = open('index.html').read()
content = re.sub(r'<link rel=\"preload\" href=\"/assets/home_wallpaper_dark.webp\".*?>', '', content)
content = re.sub(r'<link rel=\"preload\" href=\"/assets/home-wallpaper-light.webp\".*?>', '', content)
# Clean up extra newlines if possible
open('index.html', 'w').write(content)

# 2. Update src/index.css
css = open('src/index.css').read()

# Replace .scanner-wallpaper
new_dark = '''
.scanner-wallpaper {
  background: radial-gradient(circle at top, #0b1536 0%, #000411 100%) !important;
  background-attachment: scroll;
}
'''
css = re.sub(r'\.scanner-wallpaper\s*{[^}]*}', new_dark.strip(), css)

# Replace .light-theme .scanner-wallpaper
new_light = '''
html.light-theme .scanner-wallpaper {
  background: radial-gradient(circle at top, #ffffff 0%, #eef2fa 100%) !important;
}
'''
css = re.sub(r'html\.light-theme \.scanner-wallpaper\s*{[^}]*}', new_light.strip(), css)

open('src/index.css', 'w').write(css)
