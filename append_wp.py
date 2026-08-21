with open('src/index.css', 'a', encoding='utf-8') as f:
    f.write('''
/* ============================================
   HOME / SCANNER PAGE WALLPAPER
   ============================================ */
.scanner-wallpaper {
  position: relative;
  isolation: isolate;
}

.scanner-wallpaper::before,
.scanner-wallpaper::after {
  content: "";
  position: absolute;
  inset: 0;
  pointer-events: none;
  z-index: 0;
}

/* 1. DARK THEME WALLPAPER */
html:not(.light-theme) .scanner-wallpaper::before {
  /* Ultra-faint grid, angled lines, and subtle corner glows */
  background-image:
    linear-gradient(to right, rgba(99, 102, 241, 0.02) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(99, 102, 241, 0.02) 1px, transparent 1px),
    linear-gradient(45deg, rgba(6, 182, 212, 0.04) 1px, transparent 1px),
    linear-gradient(-45deg, rgba(168, 85, 247, 0.04) 1px, transparent 1px),
    radial-gradient(circle at 15% 15%, rgba(168, 85, 247, 0.12) 0%, transparent 35%),
    radial-gradient(circle at 85% 85%, rgba(6, 182, 212, 0.12) 0%, transparent 35%),
    radial-gradient(circle at 50% 100%, rgba(99, 102, 241, 0.10) 0%, transparent 40%);
  background-size: 80px 80px, 80px 80px, 120px 120px, 120px 120px, 100% 100%, 100% 100%, 100% 100%;
}

html:not(.light-theme) .scanner-wallpaper::after {
  /* Sparse glowing nodes */
  background-image: radial-gradient(circle, rgba(99, 102, 241, 0.15) 1.5px, transparent 1.5px);
  background-size: 160px 160px;
  background-position: -0.5px -0.5px;
}

/* 2. LIGHT THEME WALLPAPER */
html.light-theme .scanner-wallpaper::before {
  /* Extremely faint grid and very soft edge glows */
  background-image:
    linear-gradient(to right, rgba(99, 102, 241, 0.01) 1px, transparent 1px),
    linear-gradient(to bottom, rgba(99, 102, 241, 0.01) 1px, transparent 1px),
    linear-gradient(45deg, rgba(6, 182, 212, 0.02) 1px, transparent 1px),
    linear-gradient(-45deg, rgba(99, 102, 241, 0.02) 1px, transparent 1px),
    radial-gradient(circle at 10% 10%, rgba(99, 102, 241, 0.05) 0%, transparent 30%),
    radial-gradient(circle at 90% 90%, rgba(6, 182, 212, 0.04) 0%, transparent 30%);
  background-size: 80px 80px, 80px 80px, 120px 120px, 120px 120px, 100% 100%, 100% 100%;
}

html.light-theme .scanner-wallpaper::after {
  /* Very subtle node dots */
  background-image: radial-gradient(circle, rgba(99, 102, 241, 0.05) 1.5px, transparent 1.5px);
  background-size: 160px 160px;
  background-position: -0.5px -0.5px;
}
''')
