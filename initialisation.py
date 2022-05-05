import ctypes
import signature_c
from os import mkdir

SECRET_SIZE = 20
CERT_SIZE = 128

buffer_sizes = [SECRET_SIZE, CERT_SIZE, SECRET_SIZE, CERT_SIZE, CERT_SIZE]
buffer_names = ["gsk", "gpk", "alpha", "g1", "g2"]

buffers = {
    buffer_name: ctypes.create_string_buffer(buffer_size)
    for (buffer_name, buffer_size) in zip(buffer_names, buffer_sizes)
}

signature_c.pbc.authority_init(*[buffers[key] for key in buffer_names])


for directory in [
    "crypto_buffers",
    "trusted_from_trusted",
    "trusted_from_authority",
    "revoked",
    "identifiers",
    "challenges",
]:
    try:
        mkdir(directory)
    except:
        ()

for key in buffer_names:
    with open(f"./crypto_buffers/{key}_buffer", "wb") as f:
        f.write(buffers[key].raw)
