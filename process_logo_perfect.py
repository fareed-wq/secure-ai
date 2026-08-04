import sys
from rembg import remove
from PIL import Image

def process_perfect_logo(input_path, output_path):
    # 1. Remove background perfectly using rembg
    with open(input_path, 'rb') as i:
        input_data = i.read()
    
    output_data = remove(input_data)
    
    # 2. Save temporary transparent image
    temp_path = "temp_transparent.png"
    with open(temp_path, 'wb') as o:
        o.write(output_data)
        
    # 3. Process the transparent image to invert the dark text to white
    img = Image.open(temp_path).convert("RGBA")
    data = img.getdata()
    
    new_data = []
    for r, g, b, a in data:
        if a == 0:
            new_data.append((r, g, b, a))
            continue
            
        lum = (r + g + b) / 3
        # If it's the dark text (low luminance), invert it to white
        if lum < 120:
            # We want it to be white, but preserve its alpha for smooth edges
            new_data.append((255, 255, 255, a))
        else:
            # It's the green text. Keep it, maybe boost it slightly.
            new_data.append((r, min(255, int(g * 1.1)), b, a))

    img.putdata(new_data)
    img.save(output_path, "PNG")

if __name__ == "__main__":
    process_perfect_logo("C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png", "d:\\secure-AI\\public\\logo.png")
