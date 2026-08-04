from PIL import Image
import colorsys

def process_logo(input_path, output_path):
    img = Image.open(input_path).convert("RGBA")
    data = img.getdata()
    
    new_data = []
    for item in data:
        r, g, b, a = item
        
        # Calculate luminance
        lum = (r + g + b) / 3
        
        # If it's a very light pixel (background), make it transparent
        if lum > 240:
            new_data.append((255, 255, 255, 0))
        # If it's a dark pixel (the text/shield outline), invert it to white/light grey
        elif lum < 100:
            # Invert dark to light
            new_r = 255 - r
            new_g = 255 - g
            new_b = 255 - b
            # boost brightness a bit to make it pop
            new_data.append((min(255, new_r + 50), min(255, new_g + 50), min(255, new_b + 50), a))
        # Otherwise, it's the green text/icon. Let's make it a vibrant emerald/cyan to match the theme
        else:
            # We can convert to HSV to shift the hue slightly or just boost saturation
            h, s, v = colorsys.rgb_to_hsv(r/255.0, g/255.0, b/255.0)
            # The theme uses emerald/cyan. Emerald is around hue 0.4 to 0.45.
            # Boost value and saturation to make it glow
            new_r, new_g, new_b = colorsys.hsv_to_rgb(0.45, min(1.0, s * 1.5), min(1.0, v * 1.5))
            new_data.append((int(new_r * 255), int(new_g * 255), int(new_b * 255), a))
            
    img.putdata(new_data)
    img.save(output_path, "PNG")

if __name__ == "__main__":
    process_logo("C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png", "d:\\secure-AI\\public\\logo.png")
