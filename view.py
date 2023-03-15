import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


x = []


# Iterate through the campaign directory
for filename in os.listdir('campaign'):
    # Open the file
    with open('campaign/' + filename) as f:
        # Read the file
        data = json.load(f)
    
    data = data['objects'][0]

    # Add a list of all the keys of data, sorted, to x
    x.append(sorted(data.keys()))


# Get a list of strings of concatenated keys
y = ['|'.join(i) for i in x]

y = list(set(y))

# Create list of lists by splitting the strings on '|'
y = [i.split('|') for i in y]

for i in y:
    print(i)
    print()