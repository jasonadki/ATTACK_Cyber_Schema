import sqlite3
import os

conn = sqlite3.connect('ATTACK_EXPORT.sqlite3')

c = conn.cursor()


SCRIPT_FOLDER = 'SQL_Scripts'
SCRIPT_NAME = 'Data_Sources.sql'

# Load script
with open(os.path.join(SCRIPT_FOLDER, SCRIPT_NAME), 'r') as f:
    script = f.read()

# Print the results of the script
for row in c.execute(script):
    print(row)

conn.close()
