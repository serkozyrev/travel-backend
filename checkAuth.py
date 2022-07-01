import jwt, os
jwtsecret = os.getenv('jwtsecret')


def auth(token):
    decodedToken = jwt.decode(token, jwtsecret, algorithms=["HS256", ])
    id=str(decodedToken['id'])
    print(type(id))
    return id