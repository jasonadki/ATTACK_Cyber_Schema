import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


x = []

pairs = []

# Iterate through the x-mitre-data-source directory
for filename in os.listdir('attack-pattern'):
    # Read in the json file
    with open('attack-pattern/' + filename) as f:
        data = json.load(f)

    for k in data['objects'][0]['kill_chain_phases']:
        x.append(k['kill_chain_name'])

print(len(x))
print(len(set(x)))