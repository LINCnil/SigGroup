import json
import ctypes
import base64
import signature_c
from bottle import run, post, request, get, SimpleTemplate, static_file
import os
from datetime import datetime as dt
from utils import load_urls_from_yaml

ENCODING = "utf-8"

urls = load_urls_from_yaml()

hostName = urls["site"]["host_name"]
sitePort = urls["site"]["port"]


# Print the page
@get("/")
def racine():
    with open("index_site.html", "rb") as index_file:
        return SimpleTemplate(index_file.read()).render(urls=urls)


@get('/static/<filename>')
def server_static(filename):
    return static_file(filename, root='./static')


@get('/fonts/<filename>')
def server_static(filename):
    return static_file(filename, root='./static/fonts')


# Take an age and a validity duration as an input
# Generate the nonce, store it (with age and validity duration), and send it (only the nonce)
@get("/nonce")
def get_nonce():
    timestamp = dt.timestamp(dt.now())
    required_age = request.query.required_age
    validity = request.query.validity
    stored = {"required_age": required_age, "validity": int(validity)}
    nonce = str(timestamp)
    json.dump(stored, open("./challenges/" + nonce, "w"))
    return bytes(json.dumps({"nonce": nonce, "required_age": required_age}), ENCODING)


# Checks the signature sent by a trusted party
@post("/verif")
def verif():
    # First checks whether the challenge is authentic and valid
    message = request.json
    nonce = message["nonce"]
    signed_age = message["signed_age"]
    try:
        stored = json.load(open("./challenges/" + nonce, "r"))
        required_age = int(stored["required_age"])
        validity = float(stored["validity"])
    except:
        return bytes(json.dumps({"response": "CORRUPTED NONCE"}), ENCODING)
    if int(signed_age) != required_age:
        return bytes(json.dumps({"response": "CORRUPTED AGE"}), ENCODING)
    if dt.timestamp(dt.now()) > float(nonce) + validity:
        return bytes(
            json.dumps({"response": "THE TOKEN IS NOT VALID ANYMORE"}), ENCODING
        )

    # Checks whether the party is revokated: site_verify_tk returns 1 if tk is revokated, else 0
    chal_buffer = ctypes.create_string_buffer(bytes(nonce + str(signed_age), ENCODING))
    is_revoked = 0
    revoked_list = message["revoked_list"]
    for tk in revoked_list:
        is_revoked += signature_c.pbc.site_verify_tk(
            chal_buffer,
            ctypes.create_string_buffer(base64.b64decode(message["sign"])),
            ctypes.create_string_buffer(base64.b64decode(message["g2"])),
            ctypes.create_string_buffer(base64.b64decode(tk)),
        )

    if is_revoked == 1:
        return bytes(json.dumps({"response": "REVOKED"}), ENCODING)

    # Checks whether the signature matches correctly
    arguments = [
        "gpk",
        "y",
        "cert",
        "g1",
        "g2",
        "sign",
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
    sign = signature_c.pbc.site_verify_sign(
        chal_buffer,
        *[
            ctypes.create_string_buffer(base64.b64decode(message[key]))
            for key in arguments
        ]
    )
    if sign == 1:
        return bytes(json.dumps({"response": "ACCESS ALLOWED"}), ENCODING)
    else:
        return bytes(json.dumps({"response": "ERROR IN CHECKING SIGNATURE"}), ENCODING)


# Run the server
if __name__ == "__main__":
    print(f'Available on {urls["site"]["url"]} ...')
    run(host=hostName, port=sitePort, server='gunicorn', keyfile='authority.key',  certfile='authority.pem')

