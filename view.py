import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


ref_count_d = {}




var = 'attack-pattern'

for filename in os.listdir(var):
    # Open the file
    with open(f'{var}/' + filename) as f:
        # Read the file
        data = json.load(f)

        data = data['objects'][0]

        # Get a count of the number of references in each object
        ref_count = len(data['external_references'])

        # Get the UUID of the object
        uuid = data['id'].replace(f'{var}--', '')

        
        ref_count_d[uuid] = ref_count




# Sort by the key
ref_count_d = sorted(ref_count_d.items(), key=lambda x: x[1], reverse=True)

for k, v in ref_count_d:
    print(f'{k},', v)




