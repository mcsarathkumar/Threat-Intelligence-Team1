from bs4 import BeautifulSoup
import requests
import re
import csv
import os

OUTPUT_FILE_NAME = os.path.join(os.path.dirname(__file__), 'sha_values.csv')

# SHA256 RegExp
SHA_256_REGEXP = r'[A-Fa-f0-9]{64}'
# Target URL
URL = "https://bazaar.abuse.ch/browse/"

# Read URL using HTTP GET mathod
req = requests.get(URL)
# Parse html using BeautifulSoup library
soup = BeautifulSoup(req.text, "html.parser")
# Find all values in the page that matches SHA256 RegExp
sha_values = re.findall(SHA_256_REGEXP, soup.text)
# Retrive unique values from the list
sha_unique = set(sha_values)
# print(sha_values)
with open(OUTPUT_FILE_NAME, 'w', newline='') as file:
    csvwriter = csv.writer(file)
    csvwriter.writerows(map(lambda x: [x], sha_unique))
    file.close()