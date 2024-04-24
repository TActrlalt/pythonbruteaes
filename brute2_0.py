import hashlib
import binascii
import itertools
import multiprocessing
import re
from timeit import default_timer as timer
from Cryptodome.Cipher import AES

cipher_text_hex = 'ba260dd8bcaf261d228c9b74992d20dd4ed9d24c3f7cdb6777849da517f76c781e91dbea7c70739c3823df769386ebc0a90a1d1489de71490b38dc037000600f'
cipher_text = binascii.unhexlify(cipher_text_hex)
passwords = []
iterations = '65'  # Установите значение итераций
text_size = '35'  # Установите размер текста
sequence = 'GpflXJOl5w425hf5'

def decrypt_message(cipher_text, key):
    aes = AES.new(key, AES.MODE_ECB)
    return aes.decrypt(cipher_text)


def check_alphabet(text):
    if re.search(
            r'[^ +-/*!._`|/\'\\,;{}\[\]"~%^(№):&$#?=@<>абвгдеёжзийклмнопрстуфхцчшщъыьэюяАБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890\t\n\r\x0b\x0c]',
            text):
        return False
    else:
        return True


def worker(i):
    key = hashlib.pbkdf2_hmac('sha1', i.encode('utf-8'), b'SALT', int(iterations, 16), dklen=16)
    decrypted_message = decrypt_message(cipher_text, key).hex()
    message = ''.join([chr(int(decrypted_message[i:i + 2], 16)) for i in range(0, len(decrypted_message), 2)])
    if (check_alphabet(message)) or (len(message.strip()) == int(text_size, 16)) or (check_alphabet(message.strip())):
        print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||")
        print(f'Len: {len(message)}\nOpen text: {message}\nKey: {i}')
        print("|||||||||||||||||||||||||||||||||||||||||||||||||||||||")


def generate_all_sequences(characters, length):
    sequences = itertools.product(characters, repeat=length)
    return sequences
def seq(sequences):
    passwords = []
    B = 100000000
    index = 0
    for passwd in sequences:
        if index <= B:
            passwords.append(''.join(passwd))
            index += 1
        elif index > B:
 
            break
        else:
            index += 1
            continue

    return passwords, len(passwords) < B

def main():
    x = 0

    sequences = generate_all_sequences(list(sequence), 16)
    while x == 0:     
        start = timer()
        #seq(index, A,B,sequences)
        passwords, flag = seq(sequences)
        print(timer() - start)
        start = timer()
        with multiprocessing.Pool(processes=100) as pool:

            print(len(passwords))
            pool.map(worker, passwords)
            passwords.clear()

        print(timer() - start)
        if flag:
            break
        #print(index)



if __name__ == "__main__":
    main()
