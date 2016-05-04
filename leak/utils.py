import struct

# I don't know because use "i" fmt (see <https://docs.python.org/2.7/library/struct.html>)
def convert_address_to_string(address):
    return struct.pack("I", address)
