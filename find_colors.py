from PIL import Image

img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGB')
data = img.getdata()

darkest_dark = (255, 255, 255)
darkest_green = (255, 255, 255)

for r, g, b in data:
    if r > 240 and g > 240 and b > 240:
        continue # skip white bg
        
    # Is it green?
    if g > r + 15 and g > b + 10:
        if g < darkest_green[1]: # lowest green value is the most saturated core color
            darkest_green = (r, g, b)
    else:
        # Dark text
        if r + g + b < sum(darkest_dark):
            darkest_dark = (r, g, b)

print("Darkest Dark Text:", darkest_dark)
print("Darkest Green Text:", darkest_green)
