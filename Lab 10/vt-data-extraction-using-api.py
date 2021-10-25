import csv
import time

import requests

API_KEY = ''

custom_header = {'x-apikey': API_KEY}

md5_inputs = []
with open('input_md5.csv') as input_file:
    csv_input = csv.reader(input_file)
    for md5 in csv_input:
        md5_inputs.append(md5[0])

with open('output.csv', 'w', newline='') as output_csv:
    fieldnames = ['md5', 'type_description', 'vhash', 'creation_date', 'last_modification_date', 'type_tag', 'size', 'suggested_threat_label', 'meaningful_name', 'sha256', 'type_extension', 'last_analysis_date', 'first_submission_date', 'sha1', 'imphash', 'remark']
    writer = csv.DictWriter(output_csv, fieldnames=fieldnames)
    writer.writeheader()
    for md5 in md5_inputs:
        print(md5)
        response = requests.get('https://www.virustotal.com/api/v3/search?query=' + md5, headers=custom_header)
        obj = response.json()
        if len(obj['data']) == 0:
            row = {
                'md5': md5,
                'remark': 'Not found in VirusTotal'
            }
        else:
            row = {
                'type_description': obj['data'][0]['attributes']['type_description'],
                'vhash': obj['data'][0]['attributes']['vhash'],
                'creation_date': obj['data'][0]['attributes']['creation_date'],
                'last_modification_date': obj['data'][0]['attributes']['last_modification_date'],
                'type_tag': obj['data'][0]['attributes']['type_tag'],
                'size': obj['data'][0]['attributes']['size'],
                'suggested_threat_label': obj['data'][0]['attributes']['popular_threat_classification']['suggested_threat_label'],
                'meaningful_name': obj['data'][0]['attributes']['meaningful_name'],
                'sha256': obj['data'][0]['attributes']['sha256'],
                'type_extension': obj['data'][0]['attributes']['type_extension'],
                'last_analysis_date': obj['data'][0]['attributes']['last_analysis_date'],
                'first_submission_date': obj['data'][0]['attributes']['first_submission_date'],
                'sha1': obj['data'][0]['attributes']['sha1'],
                'md5': obj['data'][0]['attributes']['md5'],
                'imphash': obj['data'][0]['attributes']['pe_info']['imphash'],
            }
        writer.writerow(row)
        time.sleep(15)
