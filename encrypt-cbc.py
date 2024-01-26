
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import secrets

BLOCK_SIZE = AES.block_size

def cbc_encrypt(key: bytes, iv: bytes, img: bytes) -> bytes:
    """
    This function encrypts the image using AES in CBC mode.
    It extracts the header from the body of the image, extracts the trailing bytes, then encrypts the body.
    The header,body and trailing characters are canatanated and returned.
    """
    assert iv is not None

    # Separate the header from the body
    header = img[:54]
    body = img[54:]

    num_trailing_bytes = len(body) % BLOCK_SIZE
    if num_trailing_bytes != 0:
        body, trailing_bytes = body[:-num_trailing_bytes], body[-num_trailing_bytes:]
    else:
        trailing_bytes = b''

    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(body)
    return header + ciphertext + trailing_bytes


def cbc_decrypt(key: bytes, iv: bytes, img: bytes) -> bytes:
    """
    This function decrypts the image using AES in CBC mode.
    It extracts the header from the body of the image, extracts the trailing bytes, then decrypts the body.
    The header, body and trailing characters are concatenated and returned.
    """
    assert iv is not None
    if len(key) != 16:
        print("Incorrect key length (it must be 16 bytes long)")
        exit(1)
    if len(iv) != 16:
        print("Incorrect IV length (it must be 16 bytes long)")
        exit(1)

    # Separate the header from the body
    header = img[:54]
    body = img[54:]

    num_trailing_bytes = len(body) % AES.block_size
    if num_trailing_bytes != 0:
        body, trailing_bytes = body[:-num_trailing_bytes], body[-num_trailing_bytes:]
    else:
        trailing_bytes = b''

    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(body)
    return header + plaintext + trailing_bytes

def checkImage():
    image = input ("\nPlease enter the filename of the .bmp image file:\n>")
    if(image[-4:] != ".bmp"):
            print("File is not a .bmp file\nExiting...")
            exit(1)
    return image

def readImage(image):
    try:
        with open(image, "rb") as f:
            img = f.read()
    except:
        print("File not found\nExiting...")
        exit(1)
    return img

def encrypting():
    # Encryption
    key_int = secrets.randbits(128)
    key = key_int.to_bytes((key_int.bit_length() + 7) // 8, 'big')
    imgName = checkImage();
    
    img = readImage(imgName);
    
    iv = get_random_bytes(BLOCK_SIZE)
    outputFile = imgName[:-4]+"_cbc.bmp"
    
    with open(outputFile, "wb") as f:
        ciphertext = cbc_encrypt(key, iv, img)
        f.write(ciphertext)
    print("\nEncrypted image saved as", outputFile)
    
    # Export the keys securely
    with open('keyfile', 'w') as kf:
        kf.write(key.hex())
    with open('ivfile', 'w') as ivf:
        ivf.write(iv.hex())
    print("\nKey and IV securely exported to keyfile and ivfile respectively")  
    print("Key (hex) :", key.hex())
    print("IV (hex) :", iv.hex())
    
def getHexInput(type):
    print("\nPlease enter the",type,"in hex format:")
    key = input (">")
    try:
        key = bytes.fromhex(key)
    except ValueError:
        print("Key is not in hex format\nExiting...")
        exit(1)
    return key

def decrypting():   
    #decryption
    imgName = checkImage();
    img = readImage(imgName);
    key = getHexInput("key")
    iv = getHexInput("IV")
    outputFile = imgName[:-4]+"_decrypted.bmp"
    print("\nDecrypting...")
    with open(outputFile, "wb") as f:
        ciphertext = cbc_decrypt(key, iv, img)
        f.write(ciphertext)
    print("\nDecrypted image saved as",outputFile)
        
def controller():
    while (True):
        choice = input("\nWould you like to encrypt(e) or decrypt(d) a file?\n(e/d):")
        if choice == "e":
            encrypting();
        elif choice == "d":
            decrypting();
        else:
            print("Exiting...")
            break;
  
if __name__ == "__main__":
    print("\nCBC image encryptor/decryptor v0.6\nby Umar Jan (github.com/umar-j)")
    controller();   

    
