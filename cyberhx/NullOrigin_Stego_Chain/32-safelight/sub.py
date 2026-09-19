from PIL import Image
import numpy as np


n = np.array(
	Image.open('./negative.png'),
	dtype=np.int16,
)
p = np.array(
	Image.open('./print.png'),
	dtype=np.int16,
)
d = p - (255 - n)
m = ((d == 3) * 255).astype('uint8')

Image.fromarray(m).save('./mask3.png')