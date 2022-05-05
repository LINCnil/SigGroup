import json
import signature_c
from bottle import get, run, request, SimpleTemplate, static_file,app
from bottle_cors_plugin import cors_plugin
import ctypes
import os
import base64
from utils import load_urls_from_yaml
import shutil

ENCODING = "utf-8"

urls = load_urls_from_yaml()

hostName = urls["authority"]["host_name"]
authorityPort = urls["authority"]["port"]

SECRET_SIZE = 20
CERT_SIZE = 128

app = app()
app.install(cors_plugin('*'))

# Load crypto parameters
crypto_buffers = {}
for buffer_type in ["gsk", "gpk", "g1", "g2"]:
    with open(f"./crypto_buffers/{buffer_type}_buffer", "rb") as f:
        crypto_buffers[buffer_type] = ctypes.create_string_buffer(f.read())


# Server of the certification authority

# Print the page
@app.get("/")
def racine():
    with open("index_authority.html", "rb") as index_file:
        return SimpleTemplate(index_file.read()).render(urls=urls)


@app.get('/static/<filename>')
def server_static(filename):
    return static_file(filename, root='./static')


@app.get('/fonts/<filename>')
def server_static(filename):
    return static_file(filename, root='./static/fonts')


# Return the number of certificates (trusted parties) previously emitted
@app.get("/number_certificates")
def number_certificates():
    number = len(os.listdir("./trusted_from_authority/"))
    return bytes(json.dumps({"number": number}), ENCODING)


# Return a list of the revokation tokens previously emitted
@app.get("/revoked_list")
def revoked_list():
    revoked = []
    for revoked_token in os.listdir("./revoked/"):
        with open("./revoked/" + str(revoked_token), "rb") as f:
            revoked += [
                base64.b64encode(ctypes.create_string_buffer(f.read()).raw).decode(
                    ENCODING
                )
            ]
    return bytes(json.dumps({"revoked_list": revoked}), ENCODING)


# Return the crypto parameters (used to sign for trusted parties or check signatures for sites)
@app.get("/crypto_parameters")
def crypto_parameters():
    crypto_params = {
        key: base64.b64encode(crypto_buffers[key].raw).decode(ENCODING)
        for key in ["gpk", "g1", "g2"]
    }
    return bytes(json.dumps(crypto_params), ENCODING)


# Create a new certificate (the id of the certificate is the number of previous certificates +1)
@app.get("/new_certificate")
def new_certificate():
    # Create buffers for C code
    cert_buffers = {
        key: ctypes.create_string_buffer(CERT_SIZE) for key in ["cert", "tk"]
    }
    cert_buffers["y"] = ctypes.create_string_buffer(SECRET_SIZE)
    # Create certificate
    signature_c.pbc.new_certificate(
        *[crypto_buffers[key] for key in ["gsk", "gpk", "g1", "g2"]],
        *[cert_buffers[key] for key in ["y", "cert", "tk"]],
    )
    # Compute the number of the new certificate (increments by 1 for each new certificate)
    numero_certificat = 1
    while os.path.exists("./trusted_from_authority/" + str(numero_certificat)):
        numero_certificat += 1
    # Write new certificate
    os.mkdir(f"./trusted_from_authority/{numero_certificat}")

    for key, cert_buffer in cert_buffers.items():
        with open(
            f"./trusted_from_authority/{numero_certificat}/{key}_buffer", "wb"
        ) as f:
            f.write(cert_buffer.raw)
    cert_sent = {
        key: base64.b64encode(cert_buffers[key].raw).decode(ENCODING)
        for key in cert_buffers.keys()
    }
    cert_sent["numero"] = numero_certificat
    return cert_sent


# Revoke a certificate by adding the revokation token to a list that can be forwarded.
# Note that a certificate cannot "disappear" : once it is emitted, it can be revoked, but will still exist.
# This is
# - realistic as revoked trusted parties may still try to appear as legitimate
# - useful for the implementation as the number of a given party will never change
@app.get("/revoke")
def revoke():
    revoked_server = request.query.untrusted
    with open(f"./trusted_from_authority/{revoked_server}/tk_buffer", "rb") as f:
        tk_buffer = ctypes.create_string_buffer(f.read())
    with open(f"./revoked/{revoked_server}", "wb") as f:
        f.write(tk_buffer.raw)


# Run the server
if __name__ == "__main__":
    print(f'Create two trusted parties for testing purpose')
    new_certificate()
    new_certificate()
    shutil.copytree("./trusted_from_authority/1", "./trusted_from_trusted/1")
    shutil.copytree("./trusted_from_authority/2", "./trusted_from_trusted/2")
    print(f'Available on {urls["authority"]["url"]} ...')
    app.run(port=authorityPort, host=hostName,  server='gunicorn', keyfile='authority.key',  certfile='authority.pem')
    #Create two test trust parties

