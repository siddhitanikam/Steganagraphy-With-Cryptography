import numpy as np
from PIL import Image
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Convert encoding data into 8-bit binary
# form using ASCII value of characters
def genData(data):
    # list of binary codes
    # of given data
    newd = []

    for i in data:
        newd.append(format(i, '08b'))
    return newd

# Pixels are modified according to the
# 8-bit binary data and finally returned
def modPix(pix, data):
    datalist = genData(data)
    lendata = len(datalist)
    imdata = iter(pix)

    for i in range(lendata):
        # Extracting 3 pixels at a time
        pix = [value for value in imdata.__next__()[:3] + imdata.__next__()[:3] + imdata.__next__()[:3]]

        # Pixel value should be made
        # odd for 1 and even for 0
        for j in range(0, 8):
            if (datalist[i][j] == '0' and pix[j] % 2 != 0):
                pix[j] -= 1
            elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                if (pix[j] != 0):
                    pix[j] -= 1
                else:
                    pix[j] += 1

        # Eighth pixel of every set tells
        # whether to stop or read further.
        # 0 means keep reading; 1 means stop
        # message is over.
        if (i == lendata - 1):
            if (pix[-1] % 2 == 0):
                if (pix[-1] != 0):
                    pix[-1] -= 1
            else:
                pix[-1] += 1
        else:
            if (pix[-1] % 2 != 0):
                pix[-1] -= 1

        pix = tuple(pix)
        yield pix[0:3]
        yield pix[3:6]
        yield pix[6:9]

def encrypt_data(data, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Convert data to bytes and pad it to be a multiple of 16 bytes
    data_bytes = data.encode('utf-8') + b' ' * (16 - len(data) % 16)

    encrypted_data = encryptor.update(data_bytes) + encryptor.finalize()
    return encrypted_data

def decrypt_data(encrypted_data, key):

    try:
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data.decode().rstrip()
    except UnicodeDecodeError:
        print("Error decoding the data. The provided key may be incorrect or the data is corrupted.")
        return None

def encode_enc(image, key):
    w = image.size[0]
    (x, y) = (0, 0)

    data = input("Enter data to be encoded : ")
    if len(data) == 0:
        raise ValueError('Data is empty')

    # Convert the key to bytes
    key_bytes = key.encode('utf-8')

    encrypted_data = encrypt_data(data, key_bytes)

    for pixel in modPix(image.getdata(), encrypted_data):
        # Putting modified pixels in the new image
        image.putpixel((x, y), pixel)
        if (x == w - 1):
            x = 0
            y += 1
        else:
            x += 1

    new_img_name = input("Enter the name of the new image(with extension) : ")
    image.save(new_img_name, str(new_img_name.split(".")[1].upper()))
    print("Image encoded successfully!")

def decode(key):
    img = input("Enter image name(with extension) : ")
    image = Image.open(img, 'r')

    data = ''
    imgdata = iter(image.getdata())

    # Convert the key to bytes
    key_bytes = key.encode('utf-8')

    try:
        while (True):
            pixels = [value for value in imgdata.__next__()[:3] +
                    imgdata.__next__()[:3] +
                    imgdata.__next__()[:3]]

            # string of binary data
            binstr = ''

            for i in pixels[:8]:
                if (i % 2 == 0):
                    binstr += '0'
                else:
                    binstr += '1'

            data += binstr
            if (pixels[-1] % 2 != 0):
                decrypted_data = decrypt_data(bytes(int(data[i:i+8], 2) for i in range(0, len(data), 8)), key_bytes)
                print("Decrypted Word: " + decrypted_data.rstrip())
                return
    except StopIteration:
        print("Error: End of image data reached, but message not terminated.")
    except Exception as e:
        print(f"Error during decoding: {e}")
        
def calculate_mse(original, decoded):
    mse = np.mean((original - decoded) ** 2)
    return mse

def calculate_psnr(mse):
    max_pixel = 255.0
    psnr = 20 * np.log10(max_pixel / np.sqrt(mse))
    return psnr

def encode_dec_performance_analysis(original_image, encoded_image, decoded_image):
    # Load images
    original = np.array(original_image)
    encoded = np.array(encoded_image)
    decoded = np.array(decoded_image)

    # Calculate MSE
    mse = calculate_mse(original, decoded)
    print(f"Mean Square Error (MSE): {mse}")

    # Calculate PSNR
    psnr = calculate_psnr(mse)
    print(f"Peak Signal to Noise Ratio (PSNR): {psnr} dB")

if __name__ == "__main__":
    while True:
        choice = input("Welcome to Steganography!\n1. Encode\n2. Decode\n3. Quit\nEnter your choice (1/2/3): ")

        if choice == "1":
            img = input("Enter image name(with extension) : ")
            original_image = Image.open(img, 'r')
            #original_image.show()

            key = input("Enter AES key (32 bytes or lesser): ")
            while len(key) > 32:
                print("Invalid key length. Please enter a key of length of 32 bytes or lesser.")
                key = input("Enter AES key (32 bytes or lesser): ")
            if len(key) < 16:
                key = key.ljust(16, '0')  # Pad with zeros to make it 16 characters long
            elif len(key) < 24:
                key = key.ljust(24, '0')  # Pad with zeros to make it 24 characters long
            elif len(key) < 32:
                key = key.ljust(32, '0')  # Pad with zeros to make it 32 characters long

            encoded_image = original_image.copy()
            encode_enc(encoded_image, key)

        elif choice == "2":
            key = input("Enter AES key (32 bytes or lesser): ")
            while len(key) > 32:
                print("Invalid key length. Please enter a key of length of 32 bytes or lesser.")
                key = input("Enter AES key (32 bytes or lesser): ")
            if len(key) < 16:
                key = key.ljust(16, '0')  # Pad with zeros to make it 16 characters long
            elif len(key) < 24:
                key = key.ljust(24, '0')  # Pad with zeros to make it 24 characters long
            elif len(key) < 32:
                key = key.ljust(32, '0')  # Pad with zeros to make it 32 characters long

            decoded_image = Image.new('RGB', original_image.size)

            decode(key)
            #decoded_image.show()

            # Perform performance analysis
            encode_dec_performance_analysis(np.array(original_image), np.array(encoded_image), np.array(decoded_image))

        elif choice == "3":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")