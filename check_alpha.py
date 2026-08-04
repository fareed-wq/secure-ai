from PIL import Image
img = Image.open('d:\\secure-AI\\public\\logo-v6.png')
data = list(img.getdata())
alphas = {}
for r, g, b, a in data:
    alphas[a] = alphas.get(a, 0) + 1

print("Alpha distribution in v6:")
for a in sorted(alphas, key=alphas.get, reverse=True)[:10]:
    print(f"alpha={a}: {alphas[a]} pixels")
