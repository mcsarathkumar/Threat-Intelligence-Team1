from bs4 import BeautifulSoup
import requests
import re
import csv

SHA_256_REGEXP = r'[A-Fa-f0-9]{64}'
# Target URL
URL = "https://bazaar.abuse.ch/browse/"
OUTPUT_FILE_NAME = "sha_values.csv"

# Read URL using HTTP GET mathod
req = requests.get(URL)
# Parse html using BeautifulSoup library
soup = BeautifulSoup(req.text, "html.parser")
# Variable to store the page string
page_string = ''
# Iterate the BeaututifulSoup tag and typecase to string to search using RegExp
for i in soup:
    page_string = page_string + str(i)
# Find all values in the page that matches SHA256 RegExp
sha_values = re.findall(SHA_256_REGEXP, page_string)
# Retrive unique values from the list
sha_unique = set(sha_values)
# print(sha_values)
with open(OUTPUT_FILE_NAME, 'w', newline='') as file:
    csvwriter = csv.writer(file)
    csvwriter.writerows(map(lambda x: [x], sha_unique))