from crypto import sign_payload

def main():
    payload = {"device_id": "device-001", "status": "online"}
    signed = sign_payload(payload)
    print(signed)

if __name__ == "__main__":
    main()
