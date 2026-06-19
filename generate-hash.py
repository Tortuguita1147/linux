#!/usr/bin/env python3
import crypt
import secrets
import string

senha = "25102009Vi"

alfabeto = string.ascii_letters + string.digits + "./"
salt_random = ''.join(secrets.choice(alfabeto) for _ in range(24))

salt = f"$y$j9T${salt_random}$"

hash_gerado = crypt.crypt(senha, salt)

print(hash_gerado)
