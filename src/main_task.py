import requests
import re

input_file = 'path to your file'
session = requests.Session()
regex = r'https://bit.ly/[a-zA-Z0-9_.+-/#~]+'

with open(input_file, 'r') as f:
    file_content = f.read()
url_list = re.findall(regex, file_content)
for url in url_list:
    resp = session.head(url, allow_redirects=True)
    print(resp.url)
