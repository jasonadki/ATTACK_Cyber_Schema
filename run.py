import json
from uuid import uuid4
import os
import sqlite3

# Read in the Schema classes
from Schema import *


# Final Export
final_export = {}

final_export['MITRE_ATTACK_Collection_Layers'] = []
final_export['MITRE_Data_Sources_Collection_Layers'] = []
final_export['MITRE_Data_Source_Reference'] = []
final_export['MITRE_Data_Sources'] = []
final_export['MITRE_Data_Component'] = []


def create_database_from_dict(db_file, data_dict):
    # Connect to the database
    conn = sqlite3.connect(db_file)
    c = conn.cursor()

    # Create tables and insert data
    for table_name, rows in data_dict.items():
        if rows != []:
            # Create table
            column_names = rows[0].keys() if rows else []
            create_table_sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({','.join(column_names)})"
            c.execute(create_table_sql)

            # Insert rows
            for row in rows:
                if row:
                    column_names = row.keys()
                    values = [row[column_name] for column_name in column_names]
                    insert_sql = f"INSERT INTO {table_name} ({','.join(column_names)}) VALUES ({','.join(['?'] * len(values))})"
                    c.execute(insert_sql, values)


    # Commit changes and close connection
    conn.commit()
    conn.close()


############################################################################################
# MITRE_Data_Sources & MITRE_Data_Source_Reference & MITRE_Data_Sources_Collection_Layers &
# MITRE_Data_Sources_Platforms & MITRE_ATTACK_Platforms
############################################################################################
# Iterate through the x-mitre-data-source directory
for filename in os.listdir('x-mitre-data-source'):

    # Read in the json file
    with open('x-mitre-data-source/' + filename) as f:
        data = json.load(f)


    # Create a new MITRE_Data_Sources object
    # Data Source UUID is the ID minus the x-mitre-data-source-- prefix
    mitre_data_sources = MITRE_Data_Sources(
        UUID = data['objects'][0]['id'].replace('x-mitre-data-source--', ''),
        Description = data['objects'][0]['description'],
        Name = data['objects'][0]['name'],
        Version = data['objects'][0]['x_mitre_version'],
    )

    # Add the MITRE_Data_Sources object to the final export
    final_export['MITRE_Data_Sources'].append(mitre_data_sources.__dict__)

    # Iterate through the external references
    for external_reference in data['objects'][0]['external_references']:
        # Create a new MITRE_Data_Source_Reference object
        # Check that a description exists if not make it blank
        if 'description' in external_reference:
            description = external_reference['description']

            mitre_data_source_reference = MITRE_Data_Source_Reference(
                UUID = str(uuid4()),
                Source_Name = external_reference['source_name'],
                URL = external_reference['url'],
                Description = description,
                Data_Source_ID = mitre_data_sources.UUID,
            )

            # Add the MITRE_Data_Source_Reference object to the final export
            final_export['MITRE_Data_Source_Reference'].append(mitre_data_source_reference.__dict__)
        else:
            description = ''

            mitre_data_source_reference = MITRE_Data_Source_Reference(
                UUID = str(uuid4()),
                Source_Name = external_reference['source_name'],
                URL = external_reference['url'],
                Description = description,
                Data_Source_ID = mitre_data_sources.UUID,
            )

            # Add the MITRE_Data_Source_Reference object to the final export
            final_export['MITRE_Data_Source_Reference'].append(mitre_data_source_reference.__dict__)

    # Iterate through the collection layers
    for collection_layer in data['objects'][0]['x_mitre_collection_layers']:
        # Check if the collection layer already exists
        if not any(d['Name'] == collection_layer for d in final_export['MITRE_ATTACK_Collection_Layers']):
            # Create a new MITRE_ATTACK_Collection_Layers object
            mitre_attack_collection_layers = MITRE_ATTACK_Collection_Layers(
                UUID = str(uuid4()),
                Name = collection_layer,
            )

            # Add the MITRE_ATTACK_Collection_Layers object to the final export
            final_export['MITRE_ATTACK_Collection_Layers'].append(mitre_attack_collection_layers.__dict__)
            mitre_attack_collection_layers_UUID = mitre_attack_collection_layers.UUID

        else:
            # Get the UUID of the existing collection layer
            mitre_attack_collection_layers_UUID = [d for d in final_export['MITRE_ATTACK_Collection_Layers'] if d['Name'] == collection_layer][0]['UUID']

        # Create a new MITRE_Data_Sources_Collection_Layers object
        MITRE_data_source_collection_layer = MITRE_Data_Sources_Collection_Layers(
            Data_Source_ID = mitre_data_sources.UUID,
            Layer_ID = mitre_attack_collection_layers_UUID
        )

        # Add the MITRE_Data_Sources_Collection_Layers object to the final export
        final_export['MITRE_Data_Sources_Collection_Layers'].append(MITRE_data_source_collection_layer.__dict__)



# #######################
# # MITRE_Data_Component
# #######################
# Iterate through the x-mitre-data-component directory
for filename in os.listdir('x-mitre-data-component'):
    
    # Read in the json file
    with open('x-mitre-data-component/' + filename) as f:
        data = json.load(f)


    # Create a new MITRE_Data_Component object
    mitre_data_component = MITRE_Data_Component(
        UUID = data['objects'][0]['id'].replace('x-mitre-data-component--', ''),
        Description = data['objects'][0]['description'],
        Name = data['objects'][0]['name'],
        Version = data['objects'][0]['x_mitre_version'],
        Data_Source_ID = data['objects'][0]['x_mitre_data_source_ref'].replace('x-mitre-data-source--', ''),
    )

    # Add the MITRE_Data_Component object to the final export
    final_export['MITRE_Data_Component'].append(mitre_data_component.__dict__)




# Write the final export to a json file
with open('final_export.json', 'w') as outfile:
    json.dump(final_export, outfile, indent=4)




                
# Delete the old database
if os.path.exists('ATTACK_EXPORT.sqlite3'):
    os.remove('ATTACK_EXPORT.sqlite3')

# Create the database
create_database_from_dict('ATTACK_EXPORT.sqlite3', final_export)

