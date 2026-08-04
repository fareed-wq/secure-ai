from PIL import Image

def fix_logo():
    img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGBA')
    data = img.getdata()
    new_data = []
    
    for r, g, b, a in data:
        # The background is white (255, 255, 255). 
        # The darker the pixel or the more saturated it is, the lower the minimum RGB channel.
        # This perfectly maps anti-aliased edges to alpha!
        alpha = 255 - min(r, g, b)
        
        if alpha < 5:
            new_data.append((255, 255, 255, 0))
            continue
            
        # Distinguish green text from dark text
        if g > r + 20 and g > b + 10:
            # Green text: enhance it to emerald
            new_data.append((16, 185, 129, alpha)) # Tailwind emerald-500
        else:
            # Dark text: convert to white
            new_data.append((255, 255, 255, alpha))
            
    img.putdata(new_data)
    img.save('d:\\secure-AI\\public\\logo.png', 'PNG')

fix_logo()
