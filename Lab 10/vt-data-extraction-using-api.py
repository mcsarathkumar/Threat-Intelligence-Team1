import csv
import time
import requests

# VirusTotal API KEY
API_KEY = ''
# Setting API Key to headers so that VirusTotal will be able to Authenticate the Request
custom_header = {'x-apikey': API_KEY}

# Reading the input CSV file with md5 hashes and creating an array of those hashes
md5_inputs_list = []
with open('input_md5.csv') as input_file:
    csv_input = csv.reader(input_file)
    for md5 in csv_input:
        md5_inputs_list.append(md5[0])

md5_inputs = set(md5_inputs_list)

# Create an output file to store the VirusTotal API response
with open('output_final.csv', 'w', newline='') as output_csv:
    # Fields that are captured from VirusTotal API
    fieldnames = ['md5', 'type_description', 'vhash', 'creation_date', 'last_modification_date', 'type_tag', 'size', 'meaningful_name', 'sha256', 'type_extension', 'last_analysis_date', 'first_submission_date', 'sha1', 'imphash', 'remark']
    writer = csv.DictWriter(output_csv, fieldnames=fieldnames)
    # Writing Headers in CSV
    writer.writeheader()
    # For Each md5 hash make API call
    for md5 in md5_inputs:
        print(md5)
        response = requests.get('https://www.virustotal.com/api/v3/search?query=' + md5, headers=custom_header)
        obj = response.json()
        # If the reponse if a empty array, then write the below into the csv
        if len(obj['data']) == 0:
            row = {
                'md5': md5,
                'remark': 'Not found in VirusTotal'
            }
        # If the reponse has some valid information, filter out only the required fileds and write them to csv
        else:
            row = {
                'type_description': obj['data'][0]['attributes']['type_description'],
                'vhash': obj['data'][0]['attributes']['vhash'],
                'creation_date': obj['data'][0]['attributes']['creation_date'],
                'last_modification_date': obj['data'][0]['attributes']['last_modification_date'],
                'type_tag': obj['data'][0]['attributes']['type_tag'],
                'size': obj['data'][0]['attributes']['size'],
                'meaningful_name': obj['data'][0]['attributes']['meaningful_name'],
                'sha256': obj['data'][0]['attributes']['sha256'],
                'type_extension': obj['data'][0]['attributes']['type_extension'],
                'last_analysis_date': obj['data'][0]['attributes']['last_analysis_date'],
                'first_submission_date': obj['data'][0]['attributes']['first_submission_date'],
                'sha1': obj['data'][0]['attributes']['sha1'],
                'md5': md5,
                'imphash': obj['data'][0]['attributes']['pe_info']['imphash'],
            }
        # Write riws to csv
        writer.writerow(row)
        # Wait until 15 seconds before making the next API call, so the we abide by VirusTotal API Policy
        time.sleep(15)
