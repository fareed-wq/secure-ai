from PIL import Image

def make_transparent(img_path):
    img = Image.open(img_path).convert("RGBA")
    data = img.getdata()
    
    new_data = []
    for item in data:
        # Calculate grayscale intensity
        intensity = (item[0] + item[1] + item[2]) / 3
        # Use intensity as alpha channel to perfectly blend glowing edges without harsh cuts
        # We can scale it: if it's pure black, alpha is 0.
        # But wait, it's easier to just use the max of RGB as alpha for a black background image.
        alpha = max(item[0], item[1], item[2])
        
        # If it's completely black, make it completely transparent
        if alpha < 10:
            new_data.append((item[0], item[1], item[2], 0))
        else:
            # We preserve the original color but map the alpha smoothly based on brightness
            # This works flawlessly for removing black backgrounds on glowing images.
            new_data.append((item[0], item[1], item[2], alpha))
            
    img.putdata(new_data)
    img.save(img_path, "PNG")

make_transparent("public/logo.png")
