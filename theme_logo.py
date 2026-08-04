from PIL import Image

def theme_logo():
    img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGBA')
    data = img.getdata()
    new_data = []
    
    for r, g, b, a in data:
        dist = 255 - min(r, g, b)
        alpha = max(0, int((dist - 25) * (255.0 / 230.0)))
        
        if alpha == 0:
            new_data.append((255, 255, 255, 0))
            continue
            
        if g > r + 15 and g > b + 10:
            # Emerald 400
            new_data.append((52, 211, 153, alpha))
        else:
            # Violet 400
            new_data.append((167, 139, 250, alpha))
            
    img.putdata(new_data)
    img.save('d:\\secure-AI\\public\\logo-v4.png', 'PNG')

theme_logo()
