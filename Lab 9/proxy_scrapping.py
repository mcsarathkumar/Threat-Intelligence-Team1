import sys
import requests
from bs4 import BeautifulSoup
from random import choice

def get_proxy():
    url = 'https://www.sslproxies.org'
    r = requests.get(url)
    soup = BeautifulSoup(r.text, 'html.parser')
    return {'https': choice(list(map(lambda x:x[0]+':'+x[1], list(zip(map(lambda x:x.text, soup.findAll('td')[::8]),map(lambda x:x.text, soup.findAll('td')[1::8]))))))}

argumentList = sys.argv
print(get_proxy())