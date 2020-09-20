import requests, hashlib, string, random, uuid, time, calendar, re, json, urllib.parse
import socket, ssl, threading, os, sys, signal
from io import BytesIO
import gzip
from multiprocessing import Manager, Process, cpu_count, Value

class colors:

    ENDC     = '\33[0m'
    BOLD     = '\33[1m'
    ITALIC   = '\33[3m'
    URL      = '\33[4m'
    BLINK    = '\33[5m'
    BLINK2   = '\33[6m'
    SELECTED = '\33[7m'

    BLACK  = '\33[30m'
    RED    = '\33[31m'
    GREEN  = '\33[32m'
    YELLOW = '\33[33m'
    BLUE   = '\33[34m'
    VIOLET = '\33[35m'
    BEIGE  = '\33[36m'
    WHITE  = '\33[37m'

    BLACKBG  = '\33[40m'
    REDBG    = '\33[41m'
    GREENBG  = '\33[42m'
    YELLOWBG = '\33[43m'
    BLUEBG   = '\33[44m'
    VIOLETBG = '\33[45m'
    BEIGEBG  = '\33[46m'
    WHITEBG  = '\33[47m'

    GREY    = '\33[90m'
    RED2    = '\33[91m'
    GREEN2  = '\33[92m'
    YELLOW2 = '\33[93m'
    BLUE2   = '\33[94m'
    VIOLET2 = '\33[95m'
    BEIGE2  = '\33[96m'
    WHITE2  = '\33[97m'

    GREYBG    = '\33[100m'
    REDBG2    = '\33[101m'
    GREENBG2  = '\33[102m'
    YELLOWBG2 = '\33[103m'
    BLUEBG2   = '\33[104m'
    VIOLETBG2 = '\33[105m'
    BEIGEBG2  = '\33[106m'
    WHITEBG2  = '\33[107m'

def printc(value, color='', nonewline=None, more=''):

    end = '\n'
    if nonewline: end = ''

    if color: print(color + value + colors.ENDC + more, end=end)
    else: print(value + more, end=end)

def inputc(value, color='', more=''):

    if color: return input(color + value + colors.ENDC + more)
    else: return input(value + more) 

def RandomString(n = 10):
    letters = string.ascii_lowercase + '1234567890'
    return ''.join(random.choice(letters) for i in range(n))

def RandomStringUpper(n = 10):
    letters = string.ascii_uppercase + '1234567890'
    return ''.join(random.choice(letters) for i in range(n))

def RandomStringChars(n = 10):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(n))

def randomStringWithChar(stringLength=10):
    letters = string.ascii_lowercase + '1234567890'
    result = ''.join(random.choice(letters) for i in range(stringLength - 1))
    return RandomStringChars(1) + result

def printn(args): print(args, end='')
def ClearConsole(): printn("\033[H\033[2J")
def DeleteLine(): printn("\033[F"); print("\033[K")

def parseRequest(host: str, path: str, method: str, headers: dict, data=None, rawData=str(), cookies={}) -> bytes():

    method = method.upper()
    rawRequest = f'{method} {path} HTTP/1.1\r\n'
    if method == "GET" and (data != None or rawData != ''):
        rawQuery = ''
        if rawData != "":
            rawQuery = rawData
        else:
            i = 0
            for key, value in data.items():
                if i == len(data) - 1:
                    rawQuery += f"{key}={value}"
                else:
                    rawQuery += f"{key}={value}&"
                i += 1
        query = f"{path}?{rawQuery}"
        rawRequest = f"{method} {query} HTTP/1.1\r\n"

    rawHeaders = ''
    for key, value in headers.items():
        rawHeaders += f"{key}: {value}\r\n"

    if 'host' not in rawHeaders.lower():
        rawRequest += f"Host: {host}\r\n"

    if cookies:
        cookie = ''
        for key, value in cookies.items():
            cookie += f"{key}={value};"
        rawHeaders += f"Cookie: {cookie}\r\n"

    _data = ""
    if method == "POST" and (data != None or rawData != ""):

        if rawData != "":
            _data = rawData
        else:
            i = 0
            for key, value in data.items():
                if i == len(data) - 1:
                    _data += f"{key}={value}"
                else:
                    _data += f"{key}={value}&"
                i += 1

        btsio = BytesIO()
        g = gzip.GzipFile(fileobj=btsio, mode='w')
        g.write(bytes(_data, 'utf8'))
        g.close()
        gzipped_body = btsio.getvalue()

        if 'content-length' not in rawHeaders.lower():
            if _data == 'NULL?':
                rawHeaders += "Content-Length: #CLEN\r\n"
            else:
                rawHeaders += f"Content-Length: {str(len(gzipped_body))}\r\n"

    rawRequest += f"{rawHeaders}\r\n"
    if _data != "" and _data != "NULL?":

        encodedRequest = bytes(rawRequest, 'utf8') + gzipped_body

    return encodedRequest

class account:

    def __init__(self, username: str, password: str, version: str):
        self.target = str()
        self.fheaders = self.fetch_headers()
        self.username = username
        self.password = password
        self.cookies = dict()
        self.csrftoken = self.fheaders['csrftoken']
        self.mid = self.fheaders['mid']
        self.profile = {}
        self.UserAgent = self.randDevice().replace('(VERSION)', version)
        self.DeviceID = self.generate_device_id(self.hex_digest(username, password))
        self.guid1 = str(uuid.uuid4())
        self.guid2 = str(uuid.uuid4())
        self.guid3 = str(uuid.uuid4())
        self.checkpoint = bool()
        self.loggedIn = bool()
        self.ds_user_id = str()
        self.editData = {}

        headers = {}
        headers['User-Agent'] = self.UserAgent
        headers['Host'] = 'i.instagram.com'
        headers['x-ig-app-locale'] = 'en_SA'
        headers['x-ig-device-locale'] = 'en_SA' 
        headers['x-ig-mapped-locale'] = 'en_US'
        headers['x-pigeon-session-id'] = '29739560-730e-41dc-a065-eae576baba2c'
        headers['x-pigeon-rawclienttime'] = '1599515404.254'
        headers['x-ig-connection-speed'] = '643kbps'
        headers['x-ig-bandwidth-speed-kbps'] = '1236.889'
        headers['x-ig-bandwidth-totalbytes-b'] = '6672937'
        headers['x-ig-bandwidth-totaltime-ms'] = '7015'
        headers['x-ig-app-startup-country'] = 'SA'
        headers['x-bloks-version-id'] = '85e371bf185c688d008ad58d18c84943f3e6d568c4eecd561eb4b0677b1e4c55'
        headers['x-ig-www-claim'] = '0'
        headers['x-bloks-is-layout-rtl'] = 'false'
        headers['x-ig-device-id'] = 'f4aa25e2-1663-4545-afa4-9b770ae5476d'
        headers['x-ig-android-id'] = self.DeviceID
        headers['x-ig-connection-type'] = 'WIFI'
        headers['x-ig-capabilities'] = '3brTvw8='
        headers['x-ig-app-id'] = '567067343352427'
        headers['accept-language'] = 'en-SA, en-US'
        headers['x-mid'] = self.mid
        headers['content-type'] = 'application/x-www-form-urlencoded; charset=UTF-8' 
        headers['accept-encoding'] = 'gzip, deflate'
        headers['x-fb-http-engine'] = 'Liger'
        headers['Connection'] = 'close'
        self.headers = headers
        self.login()

    def fetch_headers(self) -> dict:
        url = 'https://i.instagram.com/api/v1/si/fetch_headers/'

        headers = {}
        headers['Host'] = 'i.instagram.com'
        headers['User-Agent'] = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:80.0) Gecko/20100101 Firefox/80.0'
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8'
        headers['Accept-Language'] = 'ar,en-US;q=0.7,en;q=0.3'
        headers['Accept-Encoding'] = 'gzip, deflate, br'
        headers['Connection'] = 'close'

        return requests.get(url, headers=headers).cookies.get_dict()

    def hex_digest(self, *args):
        m = hashlib.md5()
        m.update(b''.join([arg.encode('utf-8') for arg in args]))
        return m.hexdigest()

    def generate_device_id(self, seed):
        volatile_seed = "12345"
        m = hashlib.md5()
        m.update(seed.encode('utf-8') + volatile_seed.encode('utf-8'))
        return 'android-' + m.hexdigest()[:16]

    def randDevice(self) -> str:

        dpi = [
        '480', '320', '640', '515', '120', '160', '240', '800'
        ]
        manufacturer = [
            'HUAWEI', 'Xiaomi', 'samsung', 'OnePlus', 'LGE/lge', 'ZTE', 'HTC',
            'LENOVO', 'MOTOROLA', 'NOKIA', 'OPPO', 'SONY', 'VIVO', 'LAVA'
        ]
        
        randResolution = random.randrange(2, 9) * 180
        lowerResolution = randResolution - 180

        DEVICE = {
            'android_version': random.randrange(18, 25),
            'android_release': f'{random.randrange(1, 7)}.{random.randrange(0, 7)}',
            'dpi': f'{random.choice(dpi)}dpi',
            'resolution': f'{lowerResolution}x{randResolution}',
            'manufacturer': random.choice(manufacturer),
            'device': f'{random.choice(manufacturer)}-{RandomStringUpper(5)}',
            'model': f'{randomStringWithChar(4)}',
            'cpu': f'{RandomStringChars(2)}{random.randrange(1000, 9999)}'
        }

        if random.randrange(0, 2):
            DEVICE['android_release'] = f'{random.randrange(1, 7)}.{random.randrange(0, 7)}.{random.randrange(1, 7)}'

        USER_AGENT_BASE = (
            'Instagram (VERSION) '
            'Android ({android_version}/{android_release}; '
            '{dpi}; {resolution}; {manufacturer}; '
            '{device}; {model}; {cpu}; en_US)'
        )

        return USER_AGENT_BASE.format(**DEVICE)

    def GetProfile(self):
        res = requests.get('https://i.instagram.com/api/v1/accounts/current_user/?edit=true', headers=self.headers, cookies=self.cookies, verify=True)
        profile = {}

        username = re.findall(r'"username": "(.*?)"', res.text)[0]
        biography = re.findall(r'"biography": "(.*?)"', res.text)[0]
        full_name = re.findall(r'"full_name": "(.*?)"', res.text)[0]
        phone_number = re.findall(r'"phone_number": "(.*?)"', res.text)[0]
        email = re.findall(r'"email": "(.*?)"', res.text)[0]
        gender = re.findall(r'"gender": (.*?),', res.text)[0]
        external_url = re.findall(r'"external_url": "(.*?)"', res.text)[0]
        is_verified = re.findall(r'"is_verified": (.*?),', res.text)[0]

        if username: profile['username'] = username
        if biography: profile['biography'] = biography
        else: profile['biography'] = f'Swapped By Hermes v1 @0xhades'
        if full_name: profile['full_name'] = full_name
        else: profile['full_name'] = f'{insta}'
        if phone_number: profile['phone_number'] = phone_number
        else: profile['phone_number'] = 'null'
        if email: profile['email'] = urllib.parse.quote(email)
        else: profile['email'] = 'null'
        if gender: profile['gender'] = gender
        else: profile['gender'] = 'null'
        if external_url: profile['external_url'] = external_url
        else: profile['external_url'] = f'https://i.instagram.com/0xhades'
        if is_verified: profile['is_verified'] = is_verified

        self.profile = profile

    def sendCode(self, url, security_code):
        postData = {}
        guid = str(uuid.uuid4())

        postData['security_code'] = security_code
        postData['guid'] = self.guid1
        postData['_csrftoken'] = self.cookies['csrftoken']
        postData['device_id'] = self.DeviceID
        
        payload = {}
        payload['signed_body'] = f'SIGNATURE.{json.dumps(postData)}'

        response = requests.post(url, headers=self.headers, cookies=self.cookies, data=payload, verify=True)
        return response

    def sendMethod(self, url, choice):
        postData = {}
        guid = str(uuid.uuid4())

        postData['choice'] = choice # (Phone number = 0, email = 1)
        postData['guid'] = self.guid1
        postData['_csrftoken'] = self.cookies['csrftoken']
        postData['device_id'] = self.DeviceID

        payload = {}
        payload['signed_body'] = f'SIGNATURE.{json.dumps(postData)}'

        return requests.post(url, headers=self.headers, cookies=self.cookies, data=payload, verify=True)        

    def check14Day(self):
        TimeStamp = calendar.timegm(time.gmtime())
        url = 'https://www.instagram.com/accounts/web_create_ajax/attempt/'

        data = f"username={self.target}&email=anadocxxlawyalh{str(random.randrange(1000, 9999))}%40hotmail.com&first_name=NoOne&opt_into_one_tap=false&enc_password=#PWD_INSTAGRAM_BROWSER:0:{TimeStamp}:{self.password}"

        headers = {}
        headers["Origin"] ="https//www.instagram.com"
        headers["X-Instagram-AJAX"] = "a546c5cc0f70"
        headers["Content-Type"] = "application/x-www-form-urlencoded"
        headers["Accept"] = "*/*"
        headers["X-Requested-With"] ="XMLHttpRequest"
        headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:76.0) Gecko/20100101 Firefox/76.0"
        headers["X-CSRFToken"] = self.csrftoken
        headers["Referer"] ="https//www.instagram.com/"
        headers["Accept-Encoding"] = 'gzip, deflate, br"'
        headers["Accept-Language"] = "ar,en-US;q=0.7,en;q=0.3"

        res = requests.post(url, data=data, headers=headers, cookies={'mid': self.mid, 'csrftoken': self.csrftoken})

        if 'username_held_by_others' in res.text:
            printc('The target is a 14 day username', colors.YELLOW)
            choice = inputc('Do want to to countiune[c](not recommended), or exit[e]? [c/e]: ', colors.YELLOW)
            if choice.lower() == 'e':
                exit()
            else:
                return True
        else: return True

    def isBlocked(self):
        url = 'https://i.instagram.com/api/v1/accounts/edit_profile/'

        data = {}
        if self.profile['phone_number'] != 'null': data['phone_number'] = self.profile['phone_number']
        if self.profile['email'] != 'null': data['email'] = self.profile['email']
        if self.profile['gender'] != 'null': data['gender'] = self.profile['gender']
        data['external_url'] = self.profile['external_url']
        data['full_name'] = self.profile['full_name']
        data['biography'] = self.profile['biography']
        data['username'] = f'{self.username}_checkblock'
        data['_uuid'] = self.ds_user_id
        data['device_id'] = self.DeviceID
        self.editData = data

        res = requests.post(url, data=data, headers=self.headers, cookies=self.cookies)

        if res.status_code == 200:
            return True
        elif res.status_code == 429: # = too many requests
            printc("The account is blocked for spamming too many requests\nTry later.", colors.RED)
            exit()

    def login(self):

        TimeStamp = calendar.timegm(time.gmtime())

        data = {}
        data['jazoest'] = '22713'
        data['phone_id'] = self.guid1
        data['enc_password'] = f'#PWD_INSTAGRAM_BROWSER:0:{TimeStamp}:{self.password}'
        data['_csrftoken'] = self.csrftoken
        data['username'] = self.username
        data['adid'] = self.guid2
        data['guid'] = self.guid3
        data['device_id'] = self.DeviceID
        data['google_tokens'] = '[]'
        data['login_attempt_count'] = '0'

        payload = {}
        payload['signed_body'] = f'SIGNATURE.{json.dumps(data)}'

        response = requests.post('https://i.instagram.com/api/v1/accounts/login/', headers=self.headers, cookies=self.fheaders, data=payload, verify=True)
        if 'logged_in_user' in response.text:
            self.loggedIn = True
            self.cookies = response.cookies.get_dict()
            self.csrftoken = self.cookies['csrftoken']
            self.ds_user_id = self.cookies['ds_user_id']
            self.GetProfile()
            printc('Logged In Successfully', colors.GREEN2)
        elif 'challenge_required' in response.text:
            self.checkpoint = True
            self.cookies = response.cookies.get_dict()

            checkpoint_path = re.findall(r'"api_path": "(.*?)"', response.text)[0]
            challenge_url = f'https://i.instagram.com/api/v1{checkpoint_path}'

            getMethods = requests.get(challenge_url, headers=self.headers, cookies=self.cookies)

            phone = bool()
            email = bool()

            step_name = getMethods.json()['step_name'] 
            if step_name == "select_verify_method":
                if "phone_number" in getMethods.text:
                    phone = True
                if "email" in getMethods.text:
                    email = True
            elif step_name == "delta_login_review":
                choice = 0
            else:
                print(f'Strange step_name: {step_name}\n Send me this {insta}')
                choice = 0

            printc('Challenge is required', colors.RED)
            if email:
                printc('1', colors.YELLOW, more=') email')
            if phone:
                printc('0', colors.YELLOW, more=') phone number')
            choice = inputc('Choose a method to unlock your account: ', colors.YELLOW)
            
            res = self.sendMethod(challenge_url, choice)
            sendto = res.json()['step_data']['contact_point']
            print(f'A code has been sent to {sendto}')
            
            code = inputc('Enter code: ', colors.YELLOW)
            response = self.sendCode(challenge_url, code)
            if 'logged_in_user' in response.text:
                self.loggedIn = True
                self.cookies = response.cookies.get_dict()
                self.csrftoken = self.cookies['csrftoken']
                self.ds_user_id = self.cookies['ds_user_id']
                self.GetProfile()
                printc('Logged In Successfully', colors.GREEN2)
            else: printc('Login failure, try again', colors.GREEN2); exit()

        elif("Incorrect Username") in response.text:
            printc("The username you entered doesn't appear to belong to an account. Please check your username and try again.", colors.RED)
            exit()
        elif('Incorrect password') in response.text:
            printc("The password you entered is incorrect. Please try again.", colors.RED)
            exit()
        elif ('inactive user') in response.text:
            printc('Your account has been disabled for violating our terms. Learn how you may be able to restore your account.', colors.RED)
            exit()
        else:
            printc(f'Unknown error: {response.text}', colors.RED)
            exit()

class fire():

    def __init__(self, headers, data, cookies, target):
        self.headers = headers
        self.data = data
        self.buffer = bytes()
        self.client = None
        self.target = target
        self.cookies = cookies

    def hermes(self): 
        host = 'i.instagram.com'
        context = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
        self.client = context.wrap_socket(s, server_hostname=host) 
        self.client.connect((host, 443)) 
        #self.client.setblocking(0)

        headers = self.headers
        headers['Connection'] = 'Keep-Alive'
        headers['Content-Encoding'] = 'gzip'
        data = self.data
        data['username'] = self.target
        payload = {}
        payload['signed_body'] = f'SIGNATURE.{json.dumps(data)}'

        packet = parseRequest('i.instagram.com', '/api/v1/accounts/edit_profile/', 'POST', headers, payload, cookies=self.cookies)
        
        t = threading.Thread(target=self.receiver, daemon=True)
        t.start()

        while True:
            if unleash:
                self.client.send(packet)
        t.join()

    def receiver(self):
        contentLength = 0

        while True:
            global counter
            self.buffer += self.client.recv(1024)
            res = self.buffer.decode()

            if contentLength == 0:
                if 'HTTP/1.1 200' in res: #success
                    printc(f'Username swapped successfully: {self.target}', colors.GREEN2)
                    printc(f'Hermes v1 By {insta}', colors.BLUE)
                    self.client.close()
                    os.kill(os.getpid(), signal.SIGKILL)
                if 'HTTP/1.1 429' in res: #spam
                    printc(f'You got blocked for spamming', colors.RED)
                    os.kill(os.getpid(), signal.SIGKILL)
                if 'HTTP/1.1 403' in res: #spam
                    printc(f'logged out for some reason', colors.RED)
                    os.kill(os.getpid(), signal.SIGKILL)
                if 'HTTP/1.1 400' in res: #trying
                   pass
                
                if 'Content-Length' in res:
                    p = re.compile(r'Content-Length: ([^\s][0-9]+)')
                    contentLength = int(p.findall(res)[0])

            if self.buffer[-(contentLength+4):][:4] == b'\r\n\r\n':

                response_body = (self.buffer[-(contentLength):]).decode()
                printc(f'Attempt: {counter}', colors.BLUE)
                counter += 1
                print(response_body)

                self.buffer = bytes()
                contentLength = 0

unleash = 0
counter = 0
acc = None
ThreadPerMoment = 0

if __name__ == '__main__':

    insta = '@0xhades'

    ClearConsole()
    print("\u001b[38;5;31m    __  __                             \u001b[0m")
    print("\u001b[38;5;31m   / / / /__  _________ ___  ___  _____\u001b[0m")
    print("\u001b[38;5;31m  / /_/ / _ \\/ ___/ __ `__ \\/ _ \\/ ___/\u001b[0m")
    print("\u001b[38;5;31m / __  /  __/ /  / / / / / /  __(__  ) \u001b[0m")
    print("\u001b[38;5;31m/_/ /_/\\___/_/  /_/ /_/ /_/\\___/____/  \u001b[0m")
    print()
    printc('Hermes Swap v1', colors.BLUE2)
    printc(f'By Hades, inst: {insta}', colors.BLUE2)
    print()

    cores = cpu_count()
    version = '155.0.0.37.107'

    username = inputc('Username: ', colors.GREEN)
    password = inputc('Password: ', colors.GREEN)

    acc = account(username, password, version)
    print()
    acc.check14Day()
    acc.isBlocked() #?????

    target = inputc('Target: ', colors.GREEN)
    print()
    acc.target = target
    ThreadPerMoment = (int(inputc('Threads: ', colors.GREEN)))

    ClearConsole()
    print("\u001b[38;5;31m    __  __                             \u001b[0m")
    print("\u001b[38;5;31m   / / / /__  _________ ___  ___  _____\u001b[0m")
    print("\u001b[38;5;31m  / /_/ / _ \\/ ___/ __ `__ \\/ _ \\/ ___/\u001b[0m")
    print("\u001b[38;5;31m / __  /  __/ /  / / / / / /  __(__  ) \u001b[0m")
    print("\u001b[38;5;31m/_/ /_/\\___/_/  /_/ /_/ /_/\\___/____/  \u001b[0m")
    print()
    printc(f'By Hades, inst: {insta}', colors.BLUE2)
    print()

    if acc.loggedIn:

        threads = []
        for i in range(ThreadPerMoment):
            runner = fire(
                    acc.headers,
                    acc.editData,
                    acc.cookies,
                    target
                )
            t = threading.Thread(target=runner.hermes)
            threads.append(t)
            t.start()

        inputc('Ready?, Click Enter...', colors.YELLOW)
        unleash = True

        for i in threads:
            i.join()

    else: printc(f'logged out for some reason', colors.RED); exit()

