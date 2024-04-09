#!/usr/bin/env python3
"""
   An example of SCRAM-SHA-256-PLUS using tls-unqiue channel binding

   Usage: Run it, edit it, run it some more.

   Author: Steve Kerrison <{firstname.lastname}[at]jcu.edu.au>

   This is an approximation of the authentication process to aid understanding.
   It is NOT an attempt to create an implementation of SCRAM.

   Right now, this is relevant to applications using TLSv1.2, as TLSv1.3 does
   not support tls-unique. Instead, that is likely to use tls-exporter method

   This file is distributed under the MIT license and should be
   accompanied by a corresponding LICENSE.txt file.
"""
import base64
import random
import secrets
import hashlib
import hmac
import re

# Some nastiness bacause I don't really want to require people to install anything to run this script.
try:
    from passlib.utils import saslprep2
except ImportError:
    from sys import stderr
    def saslprep(source, param='Value'):
        print("WARNING: Passlib not found, so saslprep is not being performed on username. If you care about that, see https://pypi.org/project/passlib/", file=stderr)
        return source

# Use reproducible numbers if RNG = random
random.seed(1337)

class Random:
    def __init__(self, pseudo=False):
        self.pseudo = pseudo

    def randbytes(self, nbytes):
        if self.pseudo:
            return random.randbytes(nbytes)
        else:
            return secrets.token_bytes(nbytes)

#
# Set up some constants
#

PSEUDORANDOM = True
RNG = Random(pseudo=PSEUDORANDOM)

# The Go SCRAM implementation uses 16 bytes. I use 18 to avoid base64 padding
NONCE_LENGTH = 18

# Let's give a good shake of salt, also avoid base64 padding for clarity
SALT_LENGTH = 33

USERNAME = 'user'
PASSWORD = 'pencil'
SALT = RNG.randbytes(SALT_LENGTH)
SALT_B64 = base64.b64encode(SALT).decode()

# 4K is a minimum requirement for some methods and will inevitably increase
ITERATIONS = 4000
# This is the client's final message in Ulfheim's TLSv1.2 example: https://tls.ulfheim.net/
TLS_UNIQUE = bytes([0xcf, 0x91, 0x96, 0x26, 0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a])

# Prepare the username per RF5802
username_prepped = saslprep(source=USERNAME, param="Username").replace(',', '=2C').replace('=','=2D')
# A true client will fail if the prepped username is empty
# A true server will reject usernames where ',' or '=' are not re-encoded as =2C and =2D.

# Generate the client nonce
c_nonce = RNG.randbytes(NONCE_LENGTH)
# From RFC5802, nonce can be any ASCII printable character except ',',
# but we use base64 which does not include that character anyway...
c_nonce_b64 = base64.b64encode(c_nonce).decode()

client_first_message_bare = f'n={username_prepped},r={c_nonce_b64}'
client_first_message = f'p=tls-unique,,{client_first_message_bare}'

print(f'''Client's first message: 

"p": Client requires channel binding
 |   "=tls-unique": Use the `tls-unique` channel binding method
 |    |     "": (Empty) authzid
 |    |      |   "n={{username}}": The username
 |    |      |    |           "r={{c_nonce}}": ASCII printable nonce, excluding commas
 |    |      |    |            |
{client_first_message}
''')

def msgbox(msg):
    lines = msg.split('\n')
    line_width = max(map(len,lines))
    padding = '=' * line_width
    return f"{padding}\n{msg}\n{padding}"

msg = '''Client -> Server
Server looks up user's salt and iteration count'''
print()
print(msgbox(msg))

# Generate the server nonce
# Obviously, the server would normally have to read the
s_nonce = RNG.randbytes(NONCE_LENGTH)
s_nonce_b64 = base64.b64encode(s_nonce).decode()

server_first_message = f'r={c_nonce_b64}{s_nonce_b64},s={SALT_B64},i={ITERATIONS}'

print(f'''
Server's first message:

 "r={{c_nonce}}{{s_nonce}}": The client nonce with server nonce appended
   |                                                 "s={{salt}}": The user's salt
   |                                                   |       
{server_first_message}
                                                                                                    |
                                                           "i={{iterations}}": Number of hash iterations''')

msg = '''Server -> Client
Client will now compute a proof and return it to the server'''
print()
print(msgbox(msg))

salted_password = hashlib.pbkdf2_hmac('sha256', PASSWORD.encode(), SALT, ITERATIONS)
#print(salted_password)
client_key = hmac.digest(salted_password, b'Client Key', 'sha256')
stored_key = hashlib.sha256(client_key).digest()
#print(client_key)
#print(stored_key)

channel_binding = b'p=tls-unique,,' + TLS_UNIQUE
#print(channel_binding)
channel_binding_repr = f'p=tls-unique,,{TLS_UNIQUE.hex()}'

print(f'''
Channel binding information:

 "p=tls-unique": Channel binding method
 |          "": (Empty) authzid
 |          |   "{{tls_unique_bytes}}": Unique TLS channel binding token (CBT). (Shown here in hex, actually raw bytes)
 |          |    |
{channel_binding_repr}
''')

channel_binding_b64 = base64.b64encode(channel_binding).decode()
client_final_message_without_proof = f'c={channel_binding_b64},r={c_nonce_b64}{s_nonce_b64}'

auth_message = f'{client_first_message_bare},{server_first_message},{client_final_message_without_proof}'

print(f'''Auth message:

{auth_message}''')

client_signature = hmac.digest(stored_key, auth_message.encode(), 'sha256')
print(client_signature)

client_proof = bytes(a ^ b for a, b in zip(client_key, client_signature))
print(client_proof)
client_proof_b64 = base64.b64encode(client_proof).decode()

client_final_message = f'{client_final_message_without_proof},p={client_proof_b64}'
print(f'''
Client final message:

 "c={{channel-binding-info}}": Base64 encoded channel binding header and data
 |                                      "r={{nonce}}": Full nonce value
 |                                       |
{client_final_message}
                                                                                            |
                                                        "p={{proof}}": Client proof (key XOR sig)
''')

print(msgbox('''Client -> Server
Server will verify channel binding and proof'''))

# Client sends second message to server


# Proof checking by server
# 1. Compute client signature. Requires auth message and stored key.
# 2. XOR with client proof to restore the candidate client key
# 3. Hash the candidate client key to create candidate stored key
# 4. Compare to actual stored key. If equal, client knows the password

server_candidate_client_key = bytes(a ^ b for a, b in zip(client_proof, client_signature))
server_candidate_stored_key = hashlib.sha256(server_candidate_client_key).digest()
#print("Stored key:", server_candidate_stored_key)
#print("Proven key:", stored_key)

# Extract CBT from client message
extracted_channel_binding_b64 = re.match(r'^c=([^,]+),', client_final_message).group(1)
extracted_channel_binding = base64.b64decode(extracted_channel_binding_b64)
extracted_cbt = re.match(b'[^,]*,,(.*)', extracted_channel_binding, re.DOTALL).group(1)
bind_result = extracted_cbt == TLS_UNIQUE
bind_str = '==' if bind_result else '!='
print(msgbox(f'''CBT comparison
{extracted_cbt} {bind_str} {TLS_UNIQUE}'''))

if bind_result:   
    print(msgbox("Channel binding verified"))
else:
    raise NotImplementedError("This demonstration doesn't tolerate failures")

if server_candidate_stored_key == stored_key:
    print(msgbox("Server verified client proof!"))
else:
    print(msgbox("Server FAILED to verify client proof!"))
    raise NotImplementedError("This demonstration doesn't tolerate failures")

# Now server provides verifier to client

server_key = hmac.digest(salted_password, b'Server Key', 'sha256')
server_signature = hmac.digest(server_key, auth_message.encode(), 'sha256')
server_signature_b64 = base64.b64encode(server_signature).decode()


server_final_message = f'v={server_signature_b64}'


print(f'''
Server final message:

 "v={{server-signature}}": Base64 encoded server signature
 |
{server_final_message}
''')

print(msgbox('''Server -> Client
Client now verifies server's proof'''))

# Proof verification by client
# 1. Compute server key from password and server-provided salt and iteration count
# 2. Compute server signature from key and auth message
# 3. Compare server signature to the one provided by the server. If equal, then server knows the password

# Extract server signature from message
extracted_server_verification = re.match(r'v=(.*)', server_final_message).group(1)
extracted_server_signature = base64.b64decode(extracted_server_verification)

if server_signature == extracted_server_signature:
    print(msgbox("Client verified server proof!"))
else:
    print(msgbox("Client FAILED to verify server proof!"))
    raise NotImplementedError("This demonstration doesn't tolerate failures")