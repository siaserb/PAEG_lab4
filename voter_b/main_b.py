import random

from b_functions import *

voters = ['A', 'B', 'C', 'D']
candidates = [0, 1]

bullet = choose_candidate(candidates)
random_strings = [generate_random_string() for i in range(5)]
message = add_random_string(bullet, random_strings[0])

private_key_b, public_key_b = generate_key_pair()

public_key_a = deserialize_public_key(receive_data(5000))
for i in range(0, 3):
    send_data(serialize_public_key(public_key_b), 5000+i)
public_key_c = deserialize_public_key(receive_data(5001))
public_key_d = deserialize_public_key(receive_data(5001))

public_keys = [public_key_d, public_key_c, public_key_b, public_key_a]

encrypted_messages_for_check = []
encrypted_message = message
for key in public_keys:
    encrypted_message = encrypt(encrypted_message, key)
    encrypted_messages_for_check.append(encrypted_message)

encrypted_message_with_string = encrypted_message
for i in range(4):
    encrypted_message_with_string = encrypt(add_random_string(encrypted_message_with_string, random_strings[i+1]), public_keys[i])

send_data(encrypted_message_with_string, 5000)

encrypted_messages_with_strings = [receive_data(i) for i in range(5000, 5004)]

decrypted_messages_without_string = []
voters_random_strings = []

for encoded_message in encrypted_messages_with_strings:
    decrypted_message = decrypt(encoded_message, private_key_b)
    voters_random_strings.append(extract_last_8_bytes(decrypted_message))
    decrypted_messages_without_string.append(remove_string(decrypted_message, 8))

check_string(random_strings[3], voters_random_strings)

random.shuffle(decrypted_messages_without_string)

for i in range(4):
    send_data(decrypted_messages_without_string[i], 5000+i)

#--------------------------------SECOND PART------------------------------------
idx = [0, 1, 2, 3]
random.shuffle(idx)

decrypted_messages = [receive_data(i) for i in range(5000, 5004)]

public_key_a_elgamal = deserialize_public_key_elgamal(receive_data(5005))
signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

for i in range(4):
    hashed_message = hash_message(decrypted_messages[i])
    verify_signature(public_key_a_elgamal, signed_messages[i], hashed_message)

decrypted_messages_b = []
for message in decrypted_messages:
    decrypted_messages_b.append(decrypt(message, private_key_b))
reorder_list(decrypted_messages_b, idx)

check_encrypted_message(encrypted_messages_for_check, decrypted_messages_b)

for i in range(4):
    send_data(decrypted_messages_b[i], 5000+i)

#--------------------------------ELGAMAL------------------------------------
private_key_elgamal, public_key_elgamal = generate_keys_elgamal()
send_data(serialize_public_key_elgamal(public_key_elgamal), 5006)

signed_messages = []
for message in decrypted_messages_b:
    signature = sign_message(private_key_elgamal, message)
    signed_messages.append(signature)
reorder_list(signed_messages, idx)

for j in range(3):
    for i in range(4):
        send_data(signed_messages[i], 5000+i)

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)


#------------------------------FINAL-------------------------------------
public_key_d_elgamal = deserialize_public_key_elgamal(receive_data(6001))
decrypted_messages_d = [receive_data(i) for i in range(5000, 5004)]
check_encrypted_message(decrypted_messages_d, encrypted_messages_for_check)
for i in range(4):
    hashed_message = hash_message(decrypted_messages_d[i])
    verify_signature(public_key_d_elgamal, signed_messages[i], hashed_message)

final_result = []
for message in decrypted_messages_d:
    final_result.append(remove_string(message, 8))
print(final_result)
