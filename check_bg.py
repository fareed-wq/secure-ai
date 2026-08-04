from PIL import Image

img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGB')
data = list(img.getdata())
width, height = img.size

print("Top-left pixel:", data[0])
print("Top-right pixel:", data[width - 1])
print("Bottom-left pixel:", data[(height - 1) * width])
print("Bottom-right pixel:", data[height * width - 1])

# Let's see how many pixels have g > 240
count_g240 = sum(1 for r, g, b in data if g > 240)
count_g250 = sum(1 for r, g, b in data if g > 250)
count_g254 = sum(1 for r, g, b in data if g > 254)

print(f"Total pixels: {width * height}")
print(f"Pixels with g > 240: {count_g240}")
print(f"Pixels with g > 250: {count_g250}")
print(f"Pixels with g > 254: {count_g254}")
