import requests
import time
import re
import yaml

config = yaml.safe_load(open("config.yml"))
kop_key = config['kop_key']

KOPEECHKA_API_TOKEN = kop_key
EMAIL_DOMAIN = "email.com"



class tempmail:
    def create_temp_email():
        response = requests.get(f"http://api.kopeechka.store/mailbox-get-email?site=streamlabs.com&mail_type={EMAIL_DOMAIN}&token={KOPEECHKA_API_TOKEN}&api=2.0")
        data = response.json()
        if data['status'] == 'OK':
            return data['mail'], data['id']
        else:
            raise Exception("Failed to create temporary email")

    def get_email_code(email_id, max_attempts=40, retry_interval=5):
        attempts = 0
        while attempts < max_attempts:
            response = requests.get(f"http://api.kopeechka.store/mailbox-get-message?id={email_id}&token={KOPEECHKA_API_TOKEN}&api=2.0")
            data = response.json()
            if data['status'] == 'OK' and 'fullmessage' in data:
                html_content = data['fullmessage']
                otp_match = re.search(r'(\d{8})', html_content)
                if otp_match:
                    return otp_match.group(1)
            attempts += 1
            time.sleep(retry_interval)
        raise Exception("Failed to retrieve OTP from email")
    
    
