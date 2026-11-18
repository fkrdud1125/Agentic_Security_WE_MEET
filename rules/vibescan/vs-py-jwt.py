import jwt
# ruleid: vs-py-jwt
jwt.decode(token, options={"verify_signature": False})
# ok: vs-py-jwt
jwt.decode(token, key, algorithms=["HS256"])
