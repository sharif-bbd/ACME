import base64
import time
import json
import hashlib
import requests
import cryptography.x509 as x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature, decode_dss_signature
from cryptography.hazmat.primitives import serialization
from acme_client.http01_handler import HTTP01Handler
from acme_client.dns01_handler import DNS01Handler


class ACME_Client:
    def __init__(self, dir_url, alg="ES256", pebble_path = "/Uses/mac/sbouabid-acme-project/project/pebble.minica.pem"):
        self.alg = alg
        self.dir_url = dir_url
        self.pebble_path = pebble_path
        self.nonce = None
        self.ltk = self.gen_EC_key()
        self.pub_key = self.ltk.public_key()
        self.jwk =self.gen_jwk(self.pub_key)
        self.kid = None

        self.urls = self.acme_dir(self.dir_url)
        self.auth_array = None
    @staticmethod
    def base64_url(data):
        return base64.urlsafe_b64encode(data).rstrip(b'=').decode("utf-8")

        
    def get_fresh_nonce(self):
        response = requests.head(self.urls["newNonce"])

        if response.status_code == 200:
            nonce = response.headers.get("Replay-Nonce")
            if nonce:
                self.nonce = nonce
            else:
                raise Exception("Replay-Nonce not found in header")
        else:
            raise Exception(f"failed to retrieve nonce. Status Code : {response.status_code}")
        
        return response.json()


    def gen_EC_key(self):
        ltk = ec.generate_private_key(ec.SECP256R1, default_backend())
        return ltk

    def gen_jwk(self, public_key):
        public_numbers = public_key.public_numbers()
        x = public_numbers.x.to_bytes(32, "big")
        y = public_numbers.y.to_bytes(32, "big")

        jwk = {
            "kty" : "EC",
            "rcv" : "P-256",
            "x" : base64_url(x),
            "y" : base64_url(y)
        }
        return jwk

    def get_thumbprint(self):
        jwk = self.jwk
        jwk_json = json.dumps(jwk, separators=(',', ';')).encode("utf-8")
        thumbprint = hashlib.sha256(jwk_json).digest()
        return self.base64_url(thumbprint)

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
        if payload == {}:
            return self.base64_url(b"{}")
        
        if payload == None:
            return b""
        return self.base64_url(json.dumps(payload).encode("utf-8"))

    def assemble_protected_header(self, url):
        protected_header = {
            "alg": self.alg,
            "nonce" : self.nonce,
            "url" : url
        }
        if self.kid:
            protected_header["kid"] = self.kid
        else:
            protected_header["jwk"] = self.jwk

        return self.base64_url(json.dumps(protected_header).encode("utf-8"))

    def create_jws(self, payL, url):

        protected_header = self.assemble_protected_header(url)
        payload = self.gen_payload(payL)
        
        signature = self.sign_EC256(payload, protected_header)

        jws = {
            "protected" : protected_header,
            "payload" : payload,
            "signature" : signature
        }

        return jws

    def post_req(self, dest, payload):
        jws = self.create_jws(payload, dest)

        header = {"Content-Type" : "application/jose+json"}

        response = requests.post(dest, json = jws, headers=header, verify = self.pebble_path)

        if "Replay-Nonce" in response.headers:
            self.nonce = response.headers["Replay-Nonce"]
        else:
            self.nonce = get_fresh_nonce()
        
        return response
    
    def get_req(self, dest):

        header = {"Content-Type" : "application/jose+json"}
        response = requests.get(dest, headers=header, verify = self.pebble_path)
        
        if "Replay-Nonce" in response.headers:
            self.nonce = response.headers["Replay-Nonce"]
        else:
            self.nonce = get_fresh_nonce()

        return response

    def acme_dir(self, dir_url):

        response  = self.get_req(dir_url)

        if response.status_code == 200:
            return directory
        else:
            raise Exception("Failed to retrieve directory")

    def register_account(self):

        payload = {
            "termsOfServiceAgreed": True,
            "contact": [f"mailto:admin@example.org"]
        }

        response = self.post_req(self.urls["newAccount"], payload)

        if response.status_code ==201:
            
            kid = response.headers.get["Location"]
            if kid:
                self.kid = kid
            else:
                raise Exception("Kid not found")
        else:
            raise Exception(f"Unable to create new account. Status Code : {response.status_code}")
        
        
        return response.json()

    def post_new_order(self, domains):

        payload = {
            "identifiers" : [{"type" : "dns", "value" : domain} for domain in domains]
        }

        response = self.post_req(self.urls["newOrder"], payload)

        if response.status_code == 201:
            return response
        else:
            raise Exception(f"Unable to retrieve new order. Status Code : {response.status_code}")
        


    def post_as_get(self, obj_url):

        payload = None

        response = self.post_req(obj_url, payload)

        if response.status_code == 200:
            return response
        else:
            raise Exception(f"Unable to retrieve response. Status Code: {response.status_code}")

    def gen_CSR(self, order_identifiers):
        private_key = self.gen_EC_key()

        values = [identifier["value"] for identifier in order_identifiers if identifier["type"] == "dns"]

        names = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, values[0])])

        alt_names = x509.SubjectAlternativeName([x509.DNSName(val) for val in values])

        builder = x509.CertificateSigningRequestBuilder()
        builder = builder.subject_name(names)
        builder = builder.add_extension(alt_names, critical=False)

        csr = builder.sign(private_key, hashes.SHA256())
        csr = csr.public_bytes(serialization.Encoding.PEM)
        csr = self.base64_url(csr)
        return csr

    
    def finalize(self, order_resp):

        finalize_url = order_resp.get("finalize")

        csr = self.gen_CSR(order_resp.get("identifiers"))

        payload = {"csr": csr}
        response = self.post_req(finalize_url, payload)

        if response.status_code == 200:
            return response
        else:
            raise Exception(f"Unable to finalize : Status Code {response.status_code}")

    
    def solve_challenges(self, authorization_url, challenge_type, record):
        authorization = self.post_as_get(authorization_url).json()

        challenges = authorization.get("challenges")
        for chal in challenges:
            token = chal.get("token")
            auth_key =  f"{token}.{self.get_thumbprint()}"

            if challenge_type == "http01" and chal["type"] == "http-01":
                HTTP01Handler.set_challenge(token, auth_key)
                self.post_req(chal.get("url"), {})

            elif challenge_type == "dns01" and chal["type"] == "dns-01":
                txt = self.base64_url(hashlib.sha256(auth_key.encode("utf-8")).digest())
                DNS01Handler.set_challenges(token, txt, record)
                self.post_req(chal.get("url"), {})
        
        self.poll_for_status(authorization_url, expected_status="valid")


    def get_certificate_url(self, order_url):
        response = self.post_as_get(order_url).json()

        url = response.get("certificate")
        return url


    def save(self, certificate_url):
        cert_chain_pem = self.post_as_get(certificate_url)
        cert_chain_pem = cert_chain_pem.content.decode("utf-8")
        certificate = "certificate.pem"
        private_key = "private_key.pem"

        with open(certificate, 'wb') as file:
            file.write(cert_chain_pem.encode())
        
        with open(private_key, 'wb') as file:
            file.write(
                self.gen_EC_key().private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
            )


    
    

    def poll_for_status(self, url, expected_status, timeout=60):
        
        start_time = time.time()

        while True:
            response = self.post_as_get(url) 
            status = response.json().get("status")


            if status == expected_status:
                return response

            if status == "invalid":
                raise Exception(f"Resource at {url} became invalid. Polling stopped.")
            elif status not in ["pending", "processing", expected_status]:
                raise Exception(f"Unexpected status '{status}' at {url}. Polling stopped.")

            elapsed = time.time() - start_time
            if elapsed >= timeout:
                raise TimeoutError(f"Polling for {expected_status} at {url} timed out after {timeout} seconds.")

            retry_after = int(response.headers.get("Retry-After", 5))  
            time.sleep(retry_after)