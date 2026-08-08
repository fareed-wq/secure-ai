from PIL import Image

img = Image.open("public/logo-transparent.png")
data = img.load()
w, h = img.size

for x in range(165, 185):
    for y in range(25, 52):
        if x < w and y < h:
            data[x, y] = (0, 0, 0, 0)

img.save("public/logo-transparent.png")
print("Arrow removed")
