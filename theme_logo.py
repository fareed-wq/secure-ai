from PIL import Image

def theme_logo_perfect():
    img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGBA')
    data = img.getdata()
    new_data = []
    
    for r, g, b, a in data:
        is_green = (g > r + 15 and g > b + 10)
        
        if is_green:
            # Original green had F_g ~ 94
            alpha_float = (255.0 - g) / (255.0 - 94.0)
            alpha = max(0, min(255, int(alpha_float * 255)))
            
            # Emerald-400
            new_data.append((52, 211, 153, alpha))
        else:
            # Original dark had F_g ~ 4
            alpha_float = (255.0 - g) / (255.0 - 4.0)
            alpha = max(0, min(255, int(alpha_float * 255)))
            
            if alpha < 5:
                new_data.append((255, 255, 255, 0))
            else:
                # Purple-400
                new_data.append((192, 132, 252, alpha))
            
    img.putdata(new_data)
    img.save('d:\\secure-AI\\public\\logo-v5.png', 'PNG')

theme_logo_perfect()
