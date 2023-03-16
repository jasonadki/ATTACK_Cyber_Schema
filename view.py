import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


x = []


# # Iterate through the campaign directory
# for filename in os.listdir('attack-pattern'):
#     # Open the file
#     with open('attack-pattern/' + filename) as f:
#         # Read the file
#         data = json.load(f)

#         data = data['objects'][0]

#         # Get a list of all the keys in the dictionary
#         for k in data.keys():
#             x.append(k)



# for i in list(set(x)):
#     print(i)



# Iterate through the campaign directory
for filename in os.listdir('attack-pattern'):
    # Open the file
    with open('attack-pattern/' + filename) as f:
        # Read the file
        data = json.load(f)

        data = data['objects'][0]

        # if x_mitre_data_sources is in the dictionary
        if 'kill_chain_phases' in data.keys():
            # print the value of x_mitre_data_sources
            print(data['kill_chain_phases'])