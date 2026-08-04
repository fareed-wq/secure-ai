from PIL import Image

def theme_logo_flawless():
    img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGBA')
    data = img.getdata()
    new_data = []
    
    BG_G = 238.0
    
    for r, g, b, a in data:
        if g >= BG_G - 4:  # Catch any noise in the 234-242 range
            new_data.append((255, 255, 255, 0))
            continue
            
        is_green = (g > r + 15 and g > b + 10)
        
        if is_green:
            clamped_g = min(BG_G, float(g))
            alpha_float = (BG_G - clamped_g) / (BG_G - 94.0)
            alpha = max(0, min(255, int(alpha_float * 255)))
            
            # Emerald-400
            new_data.append((52, 211, 153, alpha))
        else:
            clamped_g = min(BG_G, float(g))
            alpha_float = (BG_G - clamped_g) / (BG_G - 4.0)
            alpha = max(0, min(255, int(alpha_float * 255)))
            
            # Purple-400
            new_data.append((192, 132, 252, alpha))
            
    img.putdata(new_data)
    img.save('d:\\secure-AI\\public\\logo-v6.png', 'PNG')

theme_logo_flawless()
