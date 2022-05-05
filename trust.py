import json
import ctypes
import base64
import signature_c
from bottle import run, get, post, request, SimpleTemplate, static_file, app
from bottle_cors_plugin import cors_plugin
import os
from utils import load_urls_from_yaml

ENCODING = "utf-8"

urls = load_urls_from_yaml()

hostName = urls["trust"]["host_name"]
trustPort = urls["trust"]["port"]

CHALLENGE_SIZE = 128
CERT_SIZE = 128

app = app()



app.install(cors_plugin('*'))

#Create two test users of age 16 and 25
with open(f"./identifiers/Alice", "w") as f:
    f.write("25")

with open(f"./identifiers/Bob", "w") as f:
    f.write("16")

# Print the page
@app.get("/")
def racine():
    with open("index_trust.html", "rb") as index_file:
        return SimpleTemplate(index_file.read()).render(urls=urls)


@app.get('/static/<filename>')
def server_static(filename):
    return static_file(filename, root='./static')


@app.get('/fonts/<filename>')
def server_static(filename):
    return static_file(filename, root='./static/fonts')


# Generate a new user and store their age
# As of yet, no deletion or revokation is possible
# Registering an already created user will delete the previous one
@app.post("/registerAge")
def register_age():
    registered_age = request.query.registered_age
    identifier = request.query.id
    with open(f"./identifiers/{identifier}", "w") as f:
        f.write(registered_age)


# New certificate from authority (the id of the certificate is the number of previous certificates +1)
@app.post("/new_certificate")
def new_certificate():
    # Create buffers for C code
    cert_buffers = request.json
    numero_certificat = cert_buffers["numero"]
    os.mkdir(f"./trusted_from_trusted/{numero_certificat}")
    for buff in ["y", "tk", "cert"]:
        key: ctypes.create_string_buffer(base64.b64decode(cert_buffers[key]))
        with open(
            f"./trusted_from_trusted/{numero_certificat}/{buff}_buffer", "wb"
        ) as f:
            f.write(ctypes.create_string_buffer(base64.b64decode(cert_buffers[buff])))

# Return the number of certificates (trusted parties) previously emitted
@app.get("/list_users")
def list_users():
    user_list = {}
    for filename in os.listdir("./identifiers/"):
        with open(f"./identifiers/{filename}", "r") as f:
            registered_age = int(f.read())
            user_list[filename] = registered_age

    return bytes(json.dumps(user_list), ENCODING)

# Sign a received challenge if the user is registered and of age
@app.post("/sign")
def sign():
    # First checks whether the user exists. If not, say it.
    identifier = request.query.id
    try:
        with open(f"./identifiers/{identifier}", "r") as f:
            registered_age = int(f.read())
    except:
        return bytes(json.dumps({"user": 0}), ENCODING)

    # Then checks whether the registered age is above the required age. If not, say it.
    message = request.json
    required_age = int(message["required_age"])
    nonce = message["nonce"]
    if registered_age < required_age:
        return bytes(json.dumps({"user": 1, "majeur": 0}), ENCODING)

    # Loads the parameters of the required trusted pary
    trusted = request.query.trusted
    trusted_buffers = {}
    for buffer_type in ["tk", "y", "cert"]:
        with open(f"./trusted_from_trusted/{trusted}/{buffer_type}_buffer", "rb") as f:
            trusted_buffers[buffer_type] = ctypes.create_string_buffer(f.read())

    # Loads the nonce and crypto parameters
    chal_buffer = ctypes.create_string_buffer(
        bytes(nonce + str(required_age), ENCODING)
    )
    crypto_buffers = {
        key: ctypes.create_string_buffer(base64.b64decode(message[key]))
        for key in ["gpk", "g1", "g2"]
    }

    # Create empty buffers for C code
    key_list = [
        "c1",
        "c2",
        "d1",
        "d2",
        "p1",
        "p11",
        "p12",
        "p21",
        "p22",
        "th11",
        "th12",
        "th21",
        "th22",
        "g11",
        "g12",
        "h11",
        "h12",
        "g21",
        "g22",
        "h21",
        "h22",
    ]
    empty_buffers = {key: ctypes.create_string_buffer(CERT_SIZE) for key in key_list}

    signed_chal_buffer = ctypes.create_string_buffer(CHALLENGE_SIZE)

    # Sign the challenge
    signature_c.pbc.trusted_sign_challenge(
        chal_buffer,
        trusted_buffers["y"],
        trusted_buffers["cert"],
        *[crypto_buffers[key] for key in ["gpk", "g1", "g2"]],
        trusted_buffers["tk"],
        signed_chal_buffer,
        *[empty_buffers[key] for key in key_list],
    )

    # Create the returned dictionnary
    return_dict = {
        "sign": base64.b64encode(signed_chal_buffer.raw).decode(ENCODING),
        "user": 1,
        "majeur": 1,
        "signed_age": required_age,
        "nonce": nonce,
        "cert": base64.b64encode(trusted_buffers["cert"].raw).decode(ENCODING),
        "y": base64.b64encode(trusted_buffers["y"].raw).decode(ENCODING),
    }
    return_dict.update(
        {
            key: base64.b64encode(empty_buffers[key].raw).decode(ENCODING)
            for key in key_list
        }
    )
    return bytes(json.dumps(return_dict), ENCODING)


# Run the server
if __name__ == "__main__":
    print(f'Available on {urls["trust"]["url"]} ...')
    app.run(host=hostName, port=trustPort, server='gunicorn', keyfile='authority.key',  certfile='authority.pem')

