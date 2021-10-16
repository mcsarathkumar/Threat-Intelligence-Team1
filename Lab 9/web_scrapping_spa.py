from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from selenium.common.exceptions import TimeoutException
from selenium.webdriver.support.ui import WebDriverWait
from pyshadow.main import Shadow
import os
import csv
import re

# SHA256 RegExp
SHA_256_REGEXP = r'[A-Fa-f0-9]{64}'
# Chrome driver path
CHROME_DRIVER_PATH = os.path.join(os.path.dirname(__file__), 'drivers/chromedriver_94.0.4606.61.exe')
# Browser Window Resolution
BROWSER_WINDOW_RESOLUTION = '--window-size=1920,1200'
# Should browser instance open as window
IS_BROWSER_HEADLESS = False
# Browser Timeout to close
BROWSER_TIMEOUT_SECONDS = 60

# Ouput file to store all csv
OUTPUT_FILE_NAME = os.path.join(os.path.dirname(__file__), 'sha_values_spa.csv')
# Target URL
URL = 'https://www.virustotal.com/gui/search/agent%2520tesla/comments'
# Target CSS selector inside Single page application components
TARGET_CSS_SELECTOR = 'div#comment-wrapper'

# Create object with browser properties
options = Options()
options.headless = IS_BROWSER_HEADLESS
options.add_argument(BROWSER_WINDOW_RESOLUTION)
service = Service(CHROME_DRIVER_PATH)

# Instantiate Browser instance
browser = webdriver.Chrome(options=options, service=service)
# Pass browser instance to shadow dom library to search elements inside Shadow-root
shadow = Shadow(browser)
# Open URL
browser.get(URL)

try:
    # Wait until browser loads the page completely and renders, and search for the CSS selector, exit from the function only after instance is found
    WebDriverWait(browser, BROWSER_TIMEOUT_SECONDS).until(lambda x: shadow.find_element(TARGET_CSS_SELECTOR))
    # Use shadow to read all text contents from the root of html tag
    element = shadow.find_element('html')
    # Find all values in the page that matches SHA256 RegExp
    sha_values = re.findall(SHA_256_REGEXP, element.text)
    # Retrive unique values from the list
    sha_unique = set(sha_values)
    # Write the output in a csv file
    with open(OUTPUT_FILE_NAME, 'w', newline='') as file:
        csvwriter = csv.writer(file)
        csvwriter.writerows(map(lambda x: [x], sha_unique))
        file.close()

# Exception to handle in case of browser timeout
except TimeoutException:
    print("Timed out waiting for page to load")

# Close browser after all the operations
finally:
    browser.quit()