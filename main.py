import base64
import requests
from logg import CustomLogger
import json
import tls_client 
client = tls_client.Session(client_identifier='chrome_120', random_tls_extension_order=True)
Log = CustomLogger()
from bs4 import BeautifulSoup
import requests
import re
from urllib.parse import unquote
import os
API_BASE_URL = "https://api.tempmail.lol/v2"
from urllib.parse import urlparse, parse_qs
import threading
from kop import tempmail
from threading import Lock
lock = Lock()
import string, random
import yaml

config = yaml.safe_load(open("config.yml"))
screpy_key = config['screpy_key']
prxy = config['proxy']

def remove_content(filename, delete_line: str) -> None:
        with lock:
            with open(filename, "r+") as io:
                content = io.readlines()
                io.seek(0)
                for line in content:
                    if not (delete_line in line):
                        io.write(line)
                io.truncate()
                
captcha_solved_count = 0
promo_gen_count = 0
counter_lock = threading.Lock()
import threading
from timeit import default_timer as timer
from datetime import timedelta
class Streamlabs:
    def __init__(self):
        self.client = tls_client.Session(client_identifier='chrome_120', random_tls_extension_order=True)
        self.email, self.token = tempmail.create_temp_email()
        Log.info(f'Email: {self.email} | Token: {self.token[:70]}...')
        eight_digit_password_with_uppercase_lowercase_and_digits_and_special = ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=8))
        self.password = eight_digit_password_with_uppercase_lowercase_and_digits_and_special    
        self.client.proxies = {
            'http': prxy,
            'https': prxy
        }
    
    def get_xsrf_token_from_cookies(self):
        url = "https://streamlabs.com/slid/signup"
        self.client.get(url)
        
        xsrf_token = self.client.cookies.get('XSRF-TOKEN')
        cookies = self.client.cookies.get_dict()

        if xsrf_token:
            xsrf_token = xsrf_token.replace('%3D', '=')

            cookie_header = "; ".join([f"{key}={value}" for key, value in cookies.items()])
            
            request_cookies = {key: value for key, value in cookies.items()}
            
            return xsrf_token, cookie_header, request_cookies
        else:
            raise ValueError("XSRF token not found in cookies")


    def solve_turnstile(self):
        headers = {
            'Content-Type': 'application/json',
        }

        params = {
            'key': screpy_key, 
        }

        json_data = {
            'cmd': 'request.get',
            'url': 'https://streamlabs.com/slid/signup',
            'filter': [
                'javascriptReturn',
                'statusCode',
            ],
            'dontLoadMainSite': True,
            'browserActions': [
                {
                    'type': 'solve_captcha',
                    'captcha': 'turnstile',
                    'captchaData': {
                        'sitekey': '0x4AAAAAAACELUBpqiwktdQ9',
                        'invisible': True,
                    },
                },
                {
                    'type': 'execute_js',
                    'code': 'document.getElementsByName("cf-turnstile-response")[0].value',
                },
            ],
        }
        for i in range(5):
            try:
                response = self.client.post('https://publisher.scrappey.com/api/v1', params=params, headers=headers, json=json_data)
                break
            except Exception as e:
                #Log.error(f'Failed to solve Turnstile : {e}')
                continue
        
            
        try:
            javascript_return = response.json()['solution']['javascriptReturn']

            first_value = javascript_return[0]
            Log.info(f'Solved Turnstile : {first_value[:70]}...')
            global captcha_solved_count

            with counter_lock:
                captcha_solved_count += 1
            return first_value
        except Exception as e:
            Log.error(f'Failed to solve captcha : {e}')
            return self.solve_turnstile()

    def register(self):
        tokenn, cookie_header, self.request_cokkkies = self.get_xsrf_token_from_cookies()
        Log.debug(f'x-xsrf-token: {tokenn[:60]}')

        headers = {
        'accept'            : 'application/json, text/plain, */*',
        'accept-language'   : 'en-US,en;q=0.9',
        'cache-control'     : 'no-cache',
        'client-id'         : '419049641753968640',
        'content-type'      : 'application/json',
        'origin'            : 'https://streamlabs.com',
        'pragma'            : 'no-cache',
        'priority'          : 'u=1, i',
        'referer'           : 'https://streamlabs.com/',
        'sec-ch-ua'         : '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile'  : '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest'    : 'empty',
        'sec-fetch-mode'    : 'cors',
        'sec-fetch-site'    : 'same-site',
        'user-agent'        : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'x-xsrf-token'      :  tokenn,
        }
        
        try:
            tturnstile = self.solve_turnstile()
        except Exception as e:
            Log.error(f'Failed to solve captcha : {e}')
            return False

        json_data = {
        'email': self.email,
        'username': '',
        'password': 'Payiog@007',
        'agree': True,
        'agreePromotional': True,
        'dob': '',
        'captcha_token': tturnstile,
        'locale': 'en-US',
    }
        for i in range(5):
            try:
                res = self.client.post('https://api-id.streamlabs.com/v1/auth/register', headers=headers, json=json_data)
                break
            except:
                continue
        #Log.debug(f'Response : {res.json()} | {res.status_code}')
        
        if res.status_code == 200:
            Log.debug(f'Registration success: {self.email}')
        else:
            Log.error(f'Registration failed : {res.text} | {res.status_code}')
            return False
            
        otp_verified = False
        while not otp_verified:
            otp = tempmail.get_email_code(self.token)

            if otp:

                Log.debug(f'Fetched OTP: {otp}')
                otp_verified = True
                break
            
        eVerify = f'https://api-id.streamlabs.com/v1/users/@me/email/verification/confirm'
        data = {"code":otp,"email":self.email,"tfa_code":""}
        for i in range(5):
            try:
                res = self.client.post(eVerify, headers=headers, json=data)
                break
            except:
                continue
        if res.status_code != 204:
            Log.error(f'Failed to verify Account : {res.status_code}')
            return False
        
        Log.debug(f'Verified Account : {res.status_code}')
        with open(f'accounts.txt','a') as f:
            f.write(f'{self.email}:Payiog@007\n')
            
        self.client.headers = {
        'accept'            : 'application/json, text/plain, */*',
        'accept-language'   : 'en-US,en;q=0.9',
        'cache-control'     : 'no-cache',
        'client-id'         : '419049641753968640',
        'content-type'      : 'application/json',
        'origin'            : 'https://streamlabs.com',
        'pragma'            : 'no-cache',
        'priority'          : 'u=1, i',
        'referer'           : 'https://streamlabs.com/',
        'sec-ch-ua'         : '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"',
        'sec-ch-ua-mobile'  : '?0',
        'sec-ch-ua-platform': '"Windows"',
        'sec-fetch-dest'    : 'empty',
        'sec-fetch-mode'    : 'cors',
        'sec-fetch-site'    : 'same-site',
        'user-agent'        : 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36',
        'x-xsrf-token'      :  tokenn,
        }
        try:
            csrf = self.csrf(tokenn)
        except Exception as e:
            Log.error(f'Failed to get CSRF token : {e}')
            return False
        
        if csrf:
            twitter_token = self.get_twitter_token()
            if twitter_token:
                Log.debug(f'Twitter token : {twitter_token[:50]}')
                merge = self.merge(csrf=csrf, twitter_token=twitter_token)
                if merge:
                    Log.info(f'Account Merged Successfully with token: {twitter_token[:50]}')
                    cookies = self.client.cookies
                    formatted_cookies = "; ".join([f"{cookie.name}={cookie.value}" for cookie in cookies])
                    promo = self.puller(formatted_cookies)
                    if promo:
                        self.unlink_twitter()
                else:
                    Log.error('Failed to merge accounts')
                    return False
                        
            else:
                Log.error('Failed to get Twitter token')
                return False
        else:
            Log.error('Failed to get CSRF token')
            return False
                
        

        
    def csrf(self, xsrf):
        url = "https://api-id.streamlabs.com/v1/identity/clients/419049641753968640/oauth2"
        payload = {
            "origin": "https://streamlabs.com",
            "intent": "connect",
            "state": ""
        }
        headers = {
            "X-XSRF-Token": xsrf,
            "Content-Type": "application/json"
        }
        
        # Initial POST request
        response = self.client.post(url, json=payload, headers=headers)
        #print(response.text)
        if response.status_code == 200:
            data = response.json()
            redirect_url = data.get("redirect_url")
            
            if redirect_url:
                while redirect_url:
                    redirect_response = self.client.get(redirect_url, allow_redirects=False)
                    
                    self.client.cookies.update(redirect_response.cookies)
                    #print(redirect_response.text)
                    # Check for further redirections
                    if redirect_response.status_code in (301, 302) and 'Location' in redirect_response.headers:
                        redirect_url = redirect_response.headers['Location']
                        #print(f'redirect_url : {redirect_url}')
                    else:
                        match = re.search(r"var\s+redirectUrl\s*=\s*'(.*?)';", redirect_response.text)
                        if match:
                            redirect_url = match.group(1)
                            red4 = self.client.get(redirect_url)
                            self.client.cookies.update(red4.cookies)
                            red5 = self.client.get("https://streamlabs.com/dashboard")
                            self.client.cookies.update(red5.cookies)
                            soup = BeautifulSoup(red5.text, "html.parser")
                            csrf = soup.find("meta", {"name": "csrf-token"})["content"]
                            Log.debug(f'csrf {csrf}')
                            return csrf

            else:
                print("Redirect URL not found in the response.")
                return None
        else:
            print(f"Request failed: {response.status_code} - {response.text}")
            return None
    def get_twitter_token(self):
        try:
            with open('data/tokens.txt', 'r') as f:
                tokens = f.readlines()
            if not tokens:
                Log.error("No Twitter tokens found in tokens.txt.")
                return None
            token = tokens[0].strip()
            if ':' in token:
                token = token.split(':')[-1]
            with open('data/tokens.txt', 'w') as f:
                f.writelines(tokens[1:])
            return token
        except FileNotFoundError:
            Log.error("tokens.txt file not found.")
            return None
        
    def unlink_twitter(self):
        url = 'https://streamlabs.com/api/v5/user/accounts/unlink/twitter_account'
        r = self.client.post(url=url)
        if r.status_code == 200:
            Log.debug(f'Unmerged Twitter Token: {r.json()}')
        
        else:
            Log.critical(f'Failed to unmerge : {r.json()} {r.status_code}')
        
    def merge(self,csrf,twitter_token: str) -> bool:
        try:
            response = self.client.get(
                    "https://streamlabs.com/api/v5/user/accounts/merge/twitter_account",
                    params={"r": "/dashboard#/settings/account-settings/platforms"}
                )
                
            if response.status_code != 200:
                Log.error(f"Failed to get OAuth URL: {response.status_code}")
                return False
                    
            oauth_url = response.json().get('redirect_url')
            oauth_token = oauth_url.split("oauth_token=")[1]

            session = tls_client.Session('chrome_131', random_tls_extension_order=True)

            auth_response = session.get(
                    oauth_url, 
                    headers={'cookie': f"auth_token={twitter_token};"}
                )
                
            try:
                authenticity_token = auth_response.text.split(' <input name="authenticity_token" type="hidden" value="')[1].split('">')[0]
            except IndexError:
                twitter_tokenn = self.get_twitter_token()
                Log.error("invalid acc. retrying...")
                remove_content(filename='data/tokens.txt', delete_line=twitter_token)
                return self.merge(csrf, twitter_tokenn)
                
            auth_data = {
                    'authenticity_token': authenticity_token,
                    'oauth_token': oauth_token
                }
                
            final_response = session.post('https://twitter.com/oauth/authorize', data=auth_data, headers={'cookie': f"auth_token={twitter_token};"})
            try:
                redirect_url = final_response.text.split('<p>If your browser doesn\'t redirect you please <a class="maintain-context" href="')[1].split('">')[0]
                    
                if redirect_url:
                    if 'You are being' in redirect_url:
                        print("Twitter account already used.")
                        
                        return False
                    session.headers.update({'referer': "https://twitter.com"})
                    response = self.client.get(unquote(redirect_url).replace("amp;", '').replace("amp;", ''))
                    if response.status_code == 302:
                        return True
                    else:
                        remove_content(filename='data/tokens.txt', delete_line=twitter_token)
                        print(f"Failed to link Twitter account: {response.status_code}")
                else:
                    remove_content(filename='data/tokens.txt', delete_line=twitter_token)
                    print("Failed to find redirect URL")
                    
                return False
            except IndexError:
                remove_content(filename='data/tokens.txt', delete_line=twitter_token)
                twitter_tokenn = self.get_twitter_token()
                Log.error("Failed to extract redirect URL. retrying...")
                return self.merge(csrf, twitter_tokenn)
                    
        except Exception as e:
            print(f"Failed to link Twitter account: {e}")
            return False
    def puller(self, cookiesx):
        #print(cookiesx)

        headers = {
        'Content-Type': 'application/json',
        }

        params = {
        'key': screpy_key,
        }

        json_data = {
            'cmd': 'request.get',
            'url': 'https://streamlabs.com/discord/nitro',
            'mobileProxy': True,
            'browser': [{'name': 'chrome'}],
            'noDriver': True,
            'cookies': cookiesx,
            'proxy': prxy,
        }
        response = requests.post('https://publisher.scrappey.com/api/v1', params=params, headers=headers, json=json_data)
        response.raise_for_status()  
        data = response.json()
        with open("data/promos.json","w")as f:
            json.dump(data,f,indent=4)
        promo = data['solution']['currentUrl']
        if 'https://discord.com/billing/partner-promotions/' not in promo:
            Log.warning(f'Failed to pull promo: {promo}')
            return None
        with open("promos.txt","a")as f:
            f.write(f"{promo}\n")
        Log.info(f'Successfully pulled promo code : {promo[:160]}...')
        global promo_gen_count
        with counter_lock:
            promo_gen_count += 1
        return promo
import ctypes
def update_console_title():
    start = timer()
    while True:
        with lock:
            elapsed_time = timedelta(seconds=timer() - start)
            ctypes.windll.kernel32.SetConsoleTitleW(
                f"Streamlabs Promo Gen | Coded While Shitting | Captcha Solved: {captcha_solved_count} | Promos Generated: {promo_gen_count} | Elapsed: {elapsed_time}"
            )
        time.sleep(0.1)

import threading, time
def run():
    while True:
        try:
            gen = Streamlabs()
            gen.register()
        except Exception as e:
            Log.error(f"Error in thread: {e}")
            Log.debug(f"Captcha Solved: {captcha_solved_count}, Promos Generated: {promo_gen_count}")
            time.sleep(5)
        
threads = []
thread_count = 50 if os.cpu_count() < 8 else 40
for i in range(thread_count):
    t = threading.Thread(target=run, daemon=True) 
    t.start()
    threads.append(t)
    
title_thread = threading.Thread(target=update_console_title, daemon=True)
title_thread.start()
try:
    while True:
        time.sleep(0.5)
except KeyboardInterrupt:
    print("Main program exiting. Threads will terminate.")