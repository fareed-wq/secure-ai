import re

# Fix WhatsAppWidget.jsx
wa = open('src/WhatsAppWidget.jsx').read()
wa = wa.replace('<button\n                  onClick={() => setIsOpen(false)}', '<button aria-label="Close WhatsApp Chat"\n                  onClick={() => setIsOpen(false)}')
wa = wa.replace('<motion.button\n            initial={{ scale: 0 }}', '<motion.button aria-label="Open WhatsApp Support"\n            initial={{ scale: 0 }}')
# Note: there are two motion.buttons!
# The second one is the close button:
wa = wa.replace('<motion.button aria-label="Open WhatsApp Support"\n            initial={{ scale: 0 }}\n            animate={{ scale: 1 }}\n            exit={{ scale: 0 }}\n            whileHover={{ scale: 1.05 }}\n            whileTap={{ scale: 0.95 }}\n            onClick={() => setIsOpen(false)}', '<motion.button aria-label="Close WhatsApp Support"\n            initial={{ scale: 0 }}\n            animate={{ scale: 1 }}\n            exit={{ scale: 0 }}\n            whileHover={{ scale: 1.05 }}\n            whileTap={{ scale: 0.95 }}\n            onClick={() => setIsOpen(false)}')

open('src/WhatsAppWidget.jsx', 'w').write(wa)

# Fix Sidebar.jsx
sidebar = open('src/components/layout/Sidebar.jsx').read()
# Let's just find <button and add aria-labels if missing, based on context
# There are many buttons. It's easier to use a regex to add aria-label if there's a title, or based on the icon.
def button_repl(m):
    btn = m.group(0)
    if 'aria-label' in btn: return btn
    
    label = ''
    if 'PanelLeftClose' in btn: label = 'Close Sidebar'
    elif 'PanelLeftOpen' in btn: label = 'Open Sidebar'
    elif 'Sun' in btn: label = 'Toggle Light Mode'
    elif 'Moon' in btn: label = 'Toggle Dark Mode'
    elif 'LogOut' in btn: label = 'Log Out'
    elif 'title="View"' in btn: label = 'View'
    elif 'title="Export PDF"' in btn: label = 'Export PDF'
    elif 'ChevronDown' in btn or 'ChevronRight' in btn: label = 'Expand'
    
    if label:
        return btn.replace('<button', f'<button aria-label="{label}"')
    return btn

sidebar = re.sub(r'<button[^>]*>', button_repl, sidebar)
open('src/components/layout/Sidebar.jsx', 'w').write(sidebar)

# Fix RootLayout.jsx mobile menu
root_layout = open('src/components/layout/RootLayout.jsx').read()
if 'aria-label="Open Mobile Menu"' not in root_layout:
    root_layout = root_layout.replace('<button\n            onClick={() => setIsMobileMenuOpen(true)}', '<button aria-label="Open Mobile Menu"\n            onClick={() => setIsMobileMenuOpen(true)}')
    root_layout = root_layout.replace('<button\n              onClick={() => setIsMobileMenuOpen(false)}', '<button aria-label="Close Mobile Menu"\n              onClick={() => setIsMobileMenuOpen(false)}')
open('src/components/layout/RootLayout.jsx', 'w').write(root_layout)

# Fix SaaSLayout.jsx mobile menu
saas_layout = open('src/components/layout/SaaSLayout.jsx').read()
if 'aria-label="Open Mobile Menu"' not in saas_layout:
    saas_layout = saas_layout.replace('<button\n            onClick={() => setIsMobileOpen(true)}', '<button aria-label="Open Mobile Menu"\n            onClick={() => setIsMobileOpen(true)}')
open('src/components/layout/SaaSLayout.jsx', 'w').write(saas_layout)

print('Aria labels added.')
