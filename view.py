import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


x = []

pairs = []

# Iterate through the x-mitre-data-source directory
for filename in os.listdir('relationship'):
    # Read in the json file
    with open('relationship/' + filename) as f:
        data = json.load(f)

    # Get all that is left of the first --
    sou = data['objects'][0]['source_ref'].split('--')[0]
    rel = data['objects'][0]['relationship_type']
    tar = data['objects'][0]['target_ref'].split('--')[0]

    pairs.append((sou, rel, tar))


# Get all the unique pairs
unique_pairs = list(set(pairs))

for k in unique_pairs:
    print(k)