import os
import sys


def generate_random_string(length=4):
    random_bytes = os.urandom(length)
    print(sys.getsizeof(random_bytes))
    random_hex_string = random_bytes.hex()
    print(sys.getsizeof(random_hex_string))
    return random_hex_string


a = generate_random_string()
print(a)
print(sys.getsizeof(a))
print(sys.getsizeof('784600f3'))
