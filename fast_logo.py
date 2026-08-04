from PIL import Image

def fix_logo():
    img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGBA')
    data = img.getdata()
    new_data = []
    
    for r, g, b, a in data:
        # Distance from white
        dist = 255 - min(r, g, b)
        
        # The background seems to be slightly gray, around rgb 240
        # which means dist is around 15.
        # So we subtract 25 to completely kill the background and scale the rest to 255
        alpha = max(0, int((dist - 25) * (255.0 / 230.0)))
        
        if alpha == 0:
            new_data.append((255, 255, 255, 0))
            continue
            
        # Is it green?
        if g > r + 15 and g > b + 10:
            # Green text: enhance it to emerald
            new_data.append((16, 185, 129, alpha))
        else:
            # Dark text: convert to white
            new_data.append((255, 255, 255, alpha))
            
    img.putdata(new_data)
    img.save('d:\\secure-AI\\public\\logo.png', 'PNG')

fix_logo()
