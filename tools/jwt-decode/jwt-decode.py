import jwt
import base64
import json

def decode_jwt_token():
    # Ask for JWT token input
    token = input("Please enter your JWT token: ")
    
    try:
        # First try to decode with verification using a common default key
        # This will fail for most tokens as we don't have the secret key
        decoded_token = jwt.decode(token, options={"verify_signature": False})
        print("\nDecoded JWT Token (without verification):")
        print(json.dumps(decoded_token, indent=4))
        
        # Split the token into its components
        token_parts = token.split('.')
        if len(token_parts) != 3:
            print("Warning: This doesn't appear to be a valid JWT token (should have 3 parts).")
            return
        
        # Decode header and payload manually
        header_str = token_parts[0]
        payload_str = token_parts[1]
        
        # Add padding for base64 if needed
        def add_padding(data):
            padding = len(data) % 4
            if padding:
                data += '=' * (4 - padding)
            return data
        
        # Decode header
        header_bytes = base64.b64decode(add_padding(header_str.replace('-', '+').replace('_', '/')))
        header = json.loads(header_bytes.decode('utf-8'))
        
        # Decode payload
        payload_bytes = base64.b64decode(add_padding(payload_str.replace('-', '+').replace('_', '/')))
        payload = json.loads(payload_bytes.decode('utf-8'))
        
        print("\nHeader:")
        print(json.dumps(header, indent=4))
        
        print("\nPayload:")
        print(json.dumps(payload, indent=4))
        
        print("\nSignature (base64url encoded):")
        print(token_parts[2])
        
    except jwt.DecodeError:
        print("Error: Could not decode the token.")
    except Exception as e:
        print(f"Error: {str(e)}")

if __name__ == "__main__":
    print("JWT Token Decoder")
    print("=================")
    
    try:
        # Check if PyJWT is installed
        import jwt
    except ImportError:
        print("The 'PyJWT' package is required but not installed.")
        print("Please install it using: pip install PyJWT")
        exit(1)
        
    decode_jwt_token()