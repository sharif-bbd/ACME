import base64
import json
import requests
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import serialization


class ACME_Client:
    def __init__(self, url, nonce, alg="ES256"):
        self.alg = alg
        self.url = url
        self.nonce
        self.ltk = gen_EC_key()
        self.pub_key = ltk.public_key()
        self.jwk = gen_jwk(pub_key)
        self.kid = None

    @staticmethod
    def base64_url(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


    def gen_EC_key(self):
        ltk = ec.generate_private_key(ec.SECP256R1, default_backend())
        return ltk

    def gen_jwk(self, public_key):
        PK_number = public_key.public_numbers()
        x = public_numbers.x.to_bytes(32, "big")
        y = public_numbers.y.to_bytes(32, "big")

        jwk = {
            "kty" : "EC",
            "rcv" : "P-256",
            "x" : base64_url(x),
            "y" : base64_url(y)
        }
        return jwk

    def sign_EC256(self, payload, protected_header):

        sign_input = f"{protected_header}.{payload}".encode("utf-8")
        sign = self.ltk.sign(
            sign_input,
            ec.ECDSA(hashes.SHA256())
        )

        r,s = ec.utils.decode_dss_signature(sign)

        sign_bytes = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        return self.base64_url(sign_bytes)

    
    def gen_payload(self, payload):
        return self.base64_url(json.dumps(payload).encode("utf-8"))

    def assemble_protected_header(self):

        protected_header = {
            "alg": self.alg,
            "nonce" : self.nonce,
            "url" : self.url
        }

        if self.kid:
            protected_header["kid"] = self.kid
        else:
            protected_header["jwk"] = self.jwk

        return self.base64_url(json.dumps(protected_header).encode("utf-8"))

    def create_jws(self, payL):

        protected_header = self.assemble_protected_header()
        payload = self.gen_payload(payL)
        
        signature = self.sign_EC256(payload, protected_header)

        jws = {
            "protected" : protected_header,
            "payload" : payload,
            "signature" : signature
        }

        return jws

    def post_req(self, dest, payload):
        jws = self.create_jws(payload)

        header = {"Content-Type" : "application/jose+json"}

        response = requests.post(dest, json = jws, headers=header)

        if "Replay-Nonce" in response.headers:
            self.nonce = response.headers["Replay-Nonce"]
        
        return response
    
    def get_req(self, dest):

        header = {"Content-Type" : "application/jose+json"}
        response = requests.get(dest, headers=header)

        return response

    def acme_dir(self, dir_url):

        response  = requests.get(dir_url, verify="")

        if response.status_code == 200:
            return directory
        else:
            raise Exception("Failed to retrieve directory")

    def register_account(self, email):

        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:{contact_email}"]
        }

        response = self.post_req(self.url, payload)

        if response.status_code in [200, 201]:
            self.kid = response.headers.get["Location"]
        
        return response
    
    



