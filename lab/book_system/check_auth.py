from backend.auth import generate_token, verify_token


user = {
    "id": 1,
    "username": "admin",
    "role": "admin"
}

token = generate_token(user)

print("Generated token:")
print(token)

print("\nVerified token:")
print(verify_token(token))