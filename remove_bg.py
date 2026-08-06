from PIL import Image

def remove_bg(input_path, output_path):
    img = Image.open(input_path).convert("RGBA")
    data = img.getdata()
    new_data = []
    
    # Background is approx 14, 21, 39
    bg_r, bg_g, bg_b = 14, 21, 39
    
    for r, g, b, a in data:
        # Calculate distance from background
        dist = ((r - bg_r)**2 + (g - bg_g)**2 + (b - bg_b)**2)**0.5
        
        if dist < 20:
            # It's background or dots
            new_data.append((r, g, b, 0))
        elif dist < 80:
            # Anti-aliasing edge
            alpha = int((dist - 20) / 60 * 255)
            new_data.append((r, g, b, alpha))
        else:
            new_data.append((r, g, b, 255))
            
    img.putdata(new_data)
    img.save(output_path, "PNG")

if __name__ == "__main__":
    remove_bg("public/logo-new.png", "public/logo-transparent.png")
    print("Background removed")
