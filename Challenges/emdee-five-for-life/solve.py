import requests
import subprocess
from bs4 import BeautifulSoup
from hashlib import md5


URL = "http://83.136.252.32:53245/"
COOKIES = {"PHPSESSID" : "0fmtbfor1a95931peucc3otco2"}


def try_solution(hash_txt: str | None=None):
	if hash_txt is None:
		resp = requests.get(URL)
		html_text = resp.text
		soup = BeautifulSoup(html_text, features="lxml")
		hash_txt = soup.body.find('h3', attrs={'align':'center'}).text
		
	md5_hash = md5(hash_txt.encode()).hexdigest()
	
	print(f"{hash_txt} -> {md5_hash}")
	
	resp = requests.post(URL, data={"hash" : md5_hash}, cookies=COOKIES)
	soup = BeautifulSoup(resp.text, features="lxml")
	hash_txt = soup.body.find('h3', attrs={'align':'center'}).text
	
	return hash_txt, resp.text
	

if __name__ == "__main__":
	hash_txt = None
	for _ in range(2):
		hash_txt, resp = try_solution(hash_txt)
		print(resp)
