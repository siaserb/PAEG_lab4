from a_functions import *
import sys
import random

voters = ['A', 'B', 'C', 'D']
candidates = [0, 1]

bullet = choose_candidate(candidates)
random_strings = [generate_random_string() for i in range(5)]

message = add_random_string(bullet, random_strings[0])

private_key_a, public_key_a = generate_key_pair()
for i in range(0, 3):
    send_data(serialize_public_key(public_key_a), 5000+i)
public_key_b = deserialize_public_key(receive_data(5000))
public_key_c = deserialize_public_key(receive_data(5000))
public_key_d = deserialize_public_key(receive_data(5000))

public_keys = [public_key_d, public_key_c, public_key_b, public_key_a]

# FcA(FcB(FcC(FcD(Ev, Rs1)))), FcB(FcC(FcD(Ev, Rs1))), FcC(FcD(Ev, Rs1)), FcD(Ev, Rs1)
encrypted_messages_for_check = []
encrypted_message = message
for key in public_keys:
    encrypted_message = encrypt(encrypted_message, key)
    encrypted_messages_for_check.append(encrypted_message)

encrypted_message_with_string = encrypted_message
for i in range(4):
    encrypted_message_with_string = encrypt(add_random_string(encrypted_message_with_string, random_strings[i+1]), public_keys[i])

encrypted_messages_with_strings = [encrypted_message_with_string, receive_data(5000), receive_data(5001), receive_data(5002)]

decrypted_messages_without_string = []
for i in range(4):
    decrypted_messages_without_string.append(remove_string(decrypt(encrypted_messages_with_strings[i], private_key_a), 8))

random.shuffle(decrypted_messages_without_string)

for i in range(4):
    send_data(decrypted_messages_without_string[i], 5000+i)

for i in range(4):
    print(sys.getsizeof(decrypted_messages_without_string[i]))

#--------------------------------SECOND PART------------------------------------
#Отримуємо повідомлення виду FcA(FcB(FcC(FcD(Ev, Rs1)))))
decrypted_messages_without_strings = [receive_data(i) for i in range(5000, 5004)]

#Приводимо до FcB(FcC(FcD(Ev, Rs1))))
decrypted_messages = []
for message in decrypted_messages_without_strings:
    decrypted_messages.append(decrypt(message, private_key_a))
    print(sys.getsizeof(decrypt(message, private_key_a)))

#Перевіряємо наявність нашого рядка серед зашифрованих
check_encrypted_message(encrypted_messages_for_check, decrypted_messages)

#Надсилаємо виборцю D розшифровані повідомлення виду FcB(FcC(FcD(Ev, Rs1))))
for i in range(4):
    send_data(decrypted_messages[i], 5000+i)

#--------------------------------ELGAMAL------------------------------------
#Генеруємо ключі для ЕЦП
private_key_elgamal, public_key_elgamal = generate_keys_elgamal()

#Надсилаємо публічний ключ виборцю B
send_data(serialize_public_key_elgamal(public_key_elgamal), 5005)

#Підписуємо розшифровані повідомлення
signed_messages = []
for message in decrypted_messages:
    signature = sign_message(private_key_elgamal, message)
    signed_messages.append(signature)

for j in range(3):
    for i in range(4):
        send_data(signed_messages[i], 5000+i)
        print(sys.getsizeof(signed_messages[i]))

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)

signed_messages = [receive_data(i) for i in range(5000, 5004)]
check_amount_of_messages(voters, signed_messages)


#------------------------------FINAL-------------------------------------
public_key_d_elgamal = deserialize_public_key_elgamal(receive_data(6000))
print(public_key_d_elgamal)

decrypted_messages_d = [receive_data(i) for i in range(5000, 5004)]
check_encrypted_message(decrypted_messages_d, encrypted_messages_for_check)
for i in range(4):
    hashed_message = hash_message(decrypted_messages_d[i])
    verify_signature(public_key_d_elgamal, signed_messages[i], hashed_message)

final_result = []
for message in decrypted_messages_d:
    final_result.append(remove_string(message, 8))
print(final_result)
