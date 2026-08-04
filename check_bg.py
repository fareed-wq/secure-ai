from PIL import Image

img = Image.open('C:\\Users\\Fareed\\.gemini\\antigravity\\brain\\d8aaf847-25fc-4042-9ba0-385b9831fcc2\\.user_uploaded\\media_1785843024026.png').convert('RGB')
data = list(img.getdata())

hist = {}
for r, g, b in data:
    hist[g] = hist.get(g, 0) + 1

# Print the top 10 most common g values
for g in sorted(hist, key=hist.get, reverse=True)[:20]:
    print(f"g={g}: {hist[g]} pixels")
