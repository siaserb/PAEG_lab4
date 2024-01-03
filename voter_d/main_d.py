from d_functions import *
import sys
import random

voters = ['A', 'B', 'C', 'D']
candidates = [0, 1]

bullet = choose_candidate(candidates)
random_strings = [generate_random_string() for i in range(5)]
message = add_random_string(bullet, random_strings[0])

private_key_d, public_key_d = generate_key_pair()

public_key_a = deserialize_public_key(receive_data(5002))
public_key_b = deserialize_public_key(receive_data(5002))
public_key_c = deserialize_public_key(receive_data(5002))
for i in range(0, 3):
    send_data(serialize_public_key(public_key_d), 5000+i)

public_keys = [public_key_d, public_key_c, public_key_b, public_key_a]

encrypted_messages_for_check = []
encrypted_message = message
for key in public_keys:
    encrypted_message = encrypt(encrypted_message, key)
    encrypted_messages_for_check.append(encrypted_message)

encrypted_message_with_string = encrypted_message
for i in range(4):
    encrypted_message_with_string = encrypt(add_random_string(encrypted_message_with_string, random_strings[i+1]), public_keys[i])


send_data(encrypted_message_with_string, 5002)

encrypted_messages_with_strings = [receive_data(i) for i in range(5000, 5004)]

decrypted_messages_without_string = []
voters_random_strings = []

for encoded_message in encrypted_messages_with_strings:
    decrypted_message = decrypt(encoded_message, private_key_d)
    voters_random_strings.append(extract_last_8_bytes(decrypted_message))
    decrypted_messages_without_string.append(remove_string(decrypted_message, 8))

check_string(random_strings[1], voters_random_strings)

random.shuffle(decrypted_messages_without_string)


for i in range(4):
    send_data(decrypted_messages_without_string[i], 5000 + i)

# #--------------------------------SECOND PART------------------------------------
signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

decrypted_messages = [receive_data(i) for i in range(5000, 5004)]
for i in range(4):
    print(sys.getsizeof(decrypted_messages[i]))

public_key_c_elgamal = deserialize_public_key_elgamal(receive_data(5006))
signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

for i in range(4):
    hashed_message = hash_message(decrypted_messages[i])
    verify_signature(public_key_c_elgamal, signed_messages[i], hashed_message)

decrypted_messages_d = []
for message in decrypted_messages:
    decrypted_messages_d.append(decrypt(message, private_key_d))
    print(sys.getsizeof(decrypt(message, private_key_d)))

check_encrypted_message(encrypted_messages_for_check, decrypted_messages_d)

# for i in range(4):
#     send_data(decrypted_messages_d[i], 5000+i)

#--------------------------------ELGAMAL------------------------------------
private_key_elgamal, public_key_elgamal = generate_keys_elgamal()
# send_data(serialize_public_key_elgamal(public_key_elgamal), 5006)

signed_messages = []
for message in decrypted_messages_d:
    signature = sign_message(private_key_elgamal, message)
    signed_messages.append(signature)

for j in range(3):
    for i in range(4):
        send_data(signed_messages[i], 5000+i)

#------------------------------FINAL-------------------------------------
for i in range(3):
    send_data(serialize_public_key_elgamal(public_key_elgamal), 6000+i)

for j in range(3):
    for i in range(4):
        send_data(decrypted_messages_d[i], 5000+i)

