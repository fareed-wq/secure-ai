import rembg
from PIL import Image, ImageOps

input_path = 'C:/Users/Fareed/.gemini/antigravity/brain/b69c3879-8a02-4a26-ab0f-dbec564beb6a/.user_uploaded/media_1787139641648.png'
output_path = 'public/favicon.ico'

print('Opening image...')
img = Image.open(input_path)

print('Removing background...')
img_no_bg = rembg.remove(img)

print('Cropping to bounding box...')
bbox = img_no_bg.getbbox()
if bbox:
    img_cropped = img_no_bg.crop(bbox)
else:
    img_cropped = img_no_bg

max_dim = max(img_cropped.size)
square_img = Image.new('RGBA', (max_dim, max_dim), (0, 0, 0, 0))
offset = ((max_dim - img_cropped.size[0]) // 2, (max_dim - img_cropped.size[1]) // 2)
square_img.paste(img_cropped, offset)

# Add minimal padding (1.5% on each side) to fill 95-98% of the canvas
pad_size = int(max_dim * 0.015)
padded_size = max_dim + pad_size * 2
final_img = Image.new('RGBA', (padded_size, padded_size), (0, 0, 0, 0))
final_img.paste(square_img, (pad_size, pad_size))

print('Resizing to 32x32...')
final_img = final_img.resize((32, 32), Image.Resampling.LANCZOS)

print('Saving...')
final_img.save(output_path, format='ICO', sizes=[(32, 32)])
print('Done!')
