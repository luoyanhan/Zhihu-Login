
import requests
import re
import base64
import time
import hashlib
import hmac
from PIL import Image
from http import cookiejar

HEADERS = {
    'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8',
    'accept-encoding': 'gzip, deflate, br',
    'accept-language': 'zh-CN,zh;q=0.9',
    'upgrade-insecure-requests': '1',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/65.0.3325.181 Safari/537.36'
    }

FORM_DATA = {
    'client_id': 'c3cef7c66a1843f8b3a9e6a1e3160e20',
    'grant_type': 'password',
    'source': 'com.zhihu.web',
    'username': '13729816315',
    'password': '19949291994929',
    'lang': 'en',
    'ref_source': 'homepage'
}
class zhihuAccount():
    def __init__(self):
        self.login_url = 'https://www.zhihu.com/signup?next=%2F'
        self.login_api = 'https://www.zhihu.com/api/v3/oauth/sign_in'
        self.session = requests.session()
        self.session.headers = HEADERS
        self.login_data = FORM_DATA

    def login(self, username=None, password=None, load_cookie=True):
        if  load_cookie and cookiejar.LWPCookieJar(filename='./cookies.txt').load():
            if self._check_login():
                return True
        self.session.headers.update({'x-xsrftoken': self._get_token(),
                                     'authorization': 'oauth c3cef7c66a1843f8b3a9e6a1e3160e20',
                                     'origin': 'https: // www.zhihu.com',
                                     'referer': 'https://www.zhihu.com/signup?next=%2F'
                                     })
        username, password = self._check_username_password(username, password)
        timestamp = str(int(time.time() * 1000))
        self.login_data.update({'username': username,
                                'password': password,
                                'captcha': self._get_captcha(headers=self.session.headers),
                                'timestamp': timestamp,
                                'signature': self._get_signature(timestamp)
                                })
        response = self.session.post(self.login_api, data=self.login_data, headers=self.session.headers)
        if re.search(r'error', response.text):
            print('登录失败')
            print(re.findall(r'"message":"(.*?)"', response.text)[0])
        elif self._check_login():
            return True
        return False

    def _get_token(self):
        response = self.session.get(self.login_url)
        token = re.findall(r'_xsrf=([\w|-]+)', response.headers['set-cookie'])[0]
        return token

    def _get_signature(self, timestamp):
        grant_type = self.login_data['grant_type']
        client_id = self.login_data['client_id']
        source = self.login_data['source']
        message = bytes(grant_type+client_id+source+timestamp, 'utf-8')
        hash = hmac.new(b'd1b964811afb40118a12068ff74a12f4', msg=message, digestmod=hashlib.sha1)
        return hash.hexdigest()

    def _get_captcha(self,headers):
        api = 'https://www.zhihu.com/api/v3/oauth/captcha?lang=en'
        response = self.session.get(api, headers=headers)
        if re.search(r'true', response.text):
            put_response = self.session.put(api, headers=headers)
            img_base64 = re.findall(r'"img_base64":"(.*?)"', put_response.text, re.S)[0].replace(r'\n', '')
            with open('./captcha.jpg', 'wb') as f:
                f.write(base64.b64decode(img_base64))
            img = Image.open('./captcha.jpg')
            img.show()
            capt = input('请输入验证码：')
            self.session.post(api, data={'input_text': capt}, headers=headers)
            return capt
        return ''

    def _check_username_password(self, username, password):
        if not username:
            username = self.login_data.get('username')
            if not username:
                username = input('请输入手机号：')
            if '+86' not in username:
                username = '+86'+username
        if not password:
            password = self.login_data.get('password')
            if not password:
                password = input('请输入密码：')
        return username, password

    def _check_login(self):
        response = self.session.get(self.login_url, allow_redirects=False)
        if response.status_code == 302:
            cookiejar.LWPCookieJar(filename='./cookies.txt').save()
            print('登录成功')
            return True
        return False

if __name__=='__main__':
    account = zhihuAccount()
    account.login()