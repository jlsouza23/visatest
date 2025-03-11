import json
import hashlib
import base64
import hmac
import urllib3
import ssl
from datetime import datetime
from time import mktime
import time as t
from wsgiref.handlers import format_date_time

# Import the centralized config
from config import CyberSourceConfig

class CyberSourcePayment:
    def __init__(self, config):
        """Initialize CyberSource Payment API credentials and HTTP pool manager."""
        self.request_host = config.request_host
        self.merchant_id = config.merchant_id
        self.merchant_key_id = config.merchant_key_id
        self.merchant_secret_key = config.merchant_secret_key
        
        self.pool_manager = urllib3.PoolManager(
            cert_reqs=ssl.CERT_REQUIRED,
            ca_certs=None
        )

    def get_time(self):
        """Generate a timestamp for the request header."""
        now = datetime.now()
        stamp = mktime(now.timetuple())
        return format_date_time(stamp)

    def get_digest(self, payload):
        """Generate a SHA-256 digest for the request body."""
        hash_obj = hashlib.sha256()
        hash_obj.update(payload.encode('utf-8'))
        return base64.b64encode(hash_obj.digest()).decode("utf-8")

    def get_signature(self, method, resource, time, digest):
        """Generate an HMAC-SHA256 signature for the request authentication."""
        signature_parts = [
            f'host: {self.request_host}',
            f'date: {time}',
            f'request-target: {method.lower()} {resource}',
            f'digest: SHA-256={digest}',
            f'v-c-merchant-id: {self.merchant_id}'
        ]

        signature_string = "\n".join(signature_parts).encode('utf-8')
        secret = base64.b64decode(self.merchant_secret_key)
        signature_hash = hmac.new(secret, signature_string, hashlib.sha256)
        signature = base64.b64encode(signature_hash.digest()).decode("utf-8")

        auth_header = (
            f'keyid="{self.merchant_key_id}", algorithm="HmacSHA256", '
            f'headers="host date request-target digest v-c-merchant-id", signature="{signature}"'
        )

        return auth_header

    def authorize_and_capture_payment(self):
        """Perform both authorization and capture in a single API request."""
        resource = "/pts/v2/payments/"
        method = "POST"
        time = self.get_time()

        payload_data = {
            "clientReferenceInformation": {
                "code": f"AUTH_CAPTURE_TEST_{int(t.time())}"  # Unique reference code
            },
            "paymentInformation": {
                "card": {
                    "number": "4111111111111111",
                    "expirationMonth": "12",
                    "expirationYear": "2031",
                    "securityCode": "123"
                }
            },
            "processingInformation": {
                "capture": True  # Authorization and capture in a single request
            },
            "orderInformation": {
                "amountDetails": {
                    "totalAmount": "100.00",
                    "currency": "BRL"
                },
                "billTo": {
                    "firstName": "John",
                    "lastName": "Doe",
                    "address1": "1 Market St",
                    "locality": "San Francisco",
                    "administrativeArea": "CA",
                    "postalCode": "94105",
                    "country": "US",
                    "email": "johndoe@example.com"
                }
            }
        }

        payload = json.dumps(payload_data)
        digest = self.get_digest(payload)

        headers = {
            "Host": self.request_host,
            "Date": time,
            "Digest": f"SHA-256={digest}",
            "v-c-merchant-id": self.merchant_id,
            "Signature": self.get_signature(method, resource, time, digest),
            "Content-Type": "application/json",
            "User-Agent": "CyberSource Python Client"
        }

        url = f"https://{self.request_host}{resource}"

        try:
            response = self.pool_manager.request(method, url, body=payload, headers=headers)
            response_data = json.loads(response.data.decode('utf-8'))

            print(f"Response Code (Auth + Capture): {response.status}")
            if 200 <= response.status <= 299:
                transaction_id = response_data.get("id")
                return {"status": "SUCCESS", "transaction_id": transaction_id, "message": "Authorization and capture successful"}
            else:
                return {"status": "FAILED", "error": response_data}
        except Exception as e:
            return {"status": "ERROR", "error": str(e)}

# Execute authorization and capture together
if __name__ == "__main__":
    config = CyberSourceConfig()
    cyber_payment = CyberSourcePayment(config)
    transaction_id = cyber_payment.authorize_and_capture_payment()
