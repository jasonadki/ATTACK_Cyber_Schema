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
final_export['MITRE_ATTACK_Platforms'] = []
final_export['MITRE_Data_Sources_Platforms'] = []
final_export['MITRE_TOOL'] = []
final_export['MITRE_Tool_References'] = []
final_export['MITRE_Tool_Aliases'] = []
final_export['MITRE_Tool_Platforms'] = []
final_export['MITRE_Malware'] = []
final_export['MITRE_Malware_Platforms'] = []
final_export['MITRE_Malware_Aliases'] = []
final_export['MITRE_Malware_References'] = []
final_export['MITRE_TACTIC'] = []
final_export['MITRE_Tactic_References'] = []
final_export['MITRE_Group'] = []   
final_export['MITRE_Group_Aliases'] = []
final_export['MITRE_Group_References'] = []
final_export['MITRE_Mitigation'] = []
final_export['MITRE_Mitigation_References'] = []
final_export['MITRE_ATTACK_Campaign'] = []
final_export['MITRE_ATTACK_Campaign_References'] = []
final_export['MITRE_ATTACK_Campaign_Aliases'] = []




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


    # Iterate through the platforms
    for platform in data['objects'][0]['x_mitre_platforms']:
        # Check if the platform already exists
        if not any(d['Name'] == platform for d in final_export['MITRE_ATTACK_Platforms']):
            # Create a new MITRE_ATTACK_Platforms object
            mitre_attack_platforms = MITRE_ATTACK_Platforms(
                UUID = str(uuid4()),
                Name = platform,
            )

            # Add the MITRE_ATTACK_Platforms object to the final export
            final_export['MITRE_ATTACK_Platforms'].append(mitre_attack_platforms.__dict__)
            mitre_attack_platforms_UUID = mitre_attack_platforms.UUID

        else:
            # Get the UUID of the existing platform
            mitre_attack_platforms_UUID = [d for d in final_export['MITRE_ATTACK_Platforms'] if d['Name'] == platform][0]['UUID']

        # Create a new MITRE_Data_Sources_Platforms object
        MITRE_data_source_platforms = MITRE_Data_Sources_Platforms(
            Data_Source_ID = mitre_data_sources.UUID,
            Platform_ID = mitre_attack_platforms_UUID
        )

        # Add the MITRE_Data_Sources_Platforms object to the final export
        final_export['MITRE_Data_Sources_Platforms'].append(MITRE_data_source_platforms.__dict__)




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





################################################
# MITRE_TOOL & MITRE_Tool_References &
# MITRE_Tool_Aliases & MITRE_Tool_Platforms
################################################
# Iterate through the x-mitre-tool directory
for filename in os.listdir('tool'):
        
    # Read in the json file
    with open('tool/' + filename) as f:
        data = json.load(f)


    # Create a new MITRE_TOOL object
    mitre_tool = MITRE_TOOL(
        UUID = data['objects'][0]['id'].replace('tool--', ''),
        Description = data['objects'][0]['description'],
        Name = data['objects'][0]['name'],
        Version = data['objects'][0]['x_mitre_version'],
    )

    # Add the MITRE_TOOL object to the final export
    final_export['MITRE_TOOL'].append(mitre_tool.__dict__)

    # Aliases if they exist
    if 'x_mitre_aliases' in data['objects'][0]:
        for alias in data['objects'][0]['x_mitre_aliases']:
            # Create a new MITRE_Tool_Aliases object
            mitre_tool_aliases = MITRE_Tool_Aliases(
                Name = alias,
                Tool_ID= mitre_tool.UUID,
            )

            # Add the MITRE_Tool_Aliases object to the final export
            final_export['MITRE_Tool_Aliases'].append(mitre_tool_aliases.__dict__)
                

    # References
    for reference in data['objects'][0]['external_references']:
        # Check that a description exists if not make it blank
        if 'description' in reference:
            description = reference['description']
        else:
            description = ''

        if 'url' in reference:
            url = reference['url']
        else:
            url = ''

        mitre_tool_reference = MITRE_Tool_References(
            Source_Name = reference['source_name'],
            URL = url,
            Description = description,
            Tool_ID = mitre_tool.UUID
        )


        # Add the MITRE_Tool_References object to the final export
        final_export['MITRE_Tool_References'].append(mitre_tool_reference.__dict__)


    # Platforms if they exist
    if 'x_mitre_platforms' in data['objects'][0]:
        for platform in data['objects'][0]['x_mitre_platforms']:
            # Check if the platform already exists
            if not any(d['Name'] == platform for d in final_export['MITRE_ATTACK_Platforms']):
                # Create a new MITRE_ATTACK_Platforms object
                mitre_attack_platforms = MITRE_ATTACK_Platforms(
                    UUID = str(uuid4()),
                    Name = platform,
                )

                # Add the MITRE_ATTACK_Platforms object to the final export
                final_export['MITRE_ATTACK_Platforms'].append(mitre_attack_platforms.__dict__)
                mitre_attack_platforms_UUID = mitre_attack_platforms.UUID

            else:
                # Get the UUID of the existing platform
                mitre_attack_platforms_UUID = [d for d in final_export['MITRE_ATTACK_Platforms'] if d['Name'] == platform][0]['UUID']

            # Create a new MITRE_Tool_Platforms object
            mitre_tool_platforms = MITRE_Tool_Platforms(
                Tool_ID = mitre_tool.UUID,
                Platform_ID = mitre_attack_platforms_UUID
            )

            # Add the MITRE_Tool_Platforms object to the final export
            final_export['MITRE_Tool_Platforms'].append(mitre_tool_platforms.__dict__)





####################################################
# MITRE_Malware & MITRE_Malware_Platforms &
# MITRE_Malware_Aliases & MITRE_Malware_References
####################################################
# Iterate through the malware directory
for filename in os.listdir('malware'):
    # Read in the json file
    with open('malware/' + filename) as f:
        data = json.load(f)

    
    # Create a new MITRE_Malware object
    # Check if the malware is depreciated
    if 'x_mitre_deprecated' in data['objects'][0]:
        depreciated = data['objects'][0]['x_mitre_deprecated']
    else:
        depreciated = None
    mitre_malware = MITRE_Malware(
        UUID = data['objects'][0]['id'].replace('malware--', ''),
        Description = data['objects'][0]['description'],
        Name = data['objects'][0]['name'],
        Depreciated= depreciated,
        Version_Number= data['objects'][0]['x_mitre_version'],
    )

    # Add the MITRE_Malware object to the final export
    final_export['MITRE_Malware'].append(mitre_malware.__dict__)

    # Aliases if they exist
    if 'x_mitre_aliases' in data['objects'][0]:
        for alias in data['objects'][0]['x_mitre_aliases']:
            # Create a new MITRE_Malware_Aliases object
            mitre_malware_aliases = MITRE_MALWARE_Aliases(
                Name = alias,
                Malware_ID= mitre_malware.UUID,
            )

            # Add the MITRE_Malware_Aliases object to the final export
            final_export['MITRE_Malware_Aliases'].append(mitre_malware_aliases.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for reference in data['objects'][0]['external_references']:
            # Check that a description exists if not make it blank
            if 'description' in reference:
                description = reference['description']
            else:
                description = ''

            if 'url' in reference:
                url = reference['url']
            else:
                url = ''

            mitre_malware_reference = MITRE_Malware_References(
                Source_Name = reference['source_name'],
                URL = url,
                Description = description,
                Malware_ID = mitre_malware.UUID
            )

            # Add the MITRE_Malware_References object to the final export
            final_export['MITRE_Malware_References'].append(mitre_malware_reference.__dict__)

    # Platforms if they exist
    if 'x_mitre_platforms' in data['objects'][0]:
        for platform in data['objects'][0]['x_mitre_platforms']:
            # Check if the platform already exists
            if not any(d['Name'] == platform for d in final_export['MITRE_ATTACK_Platforms']):
                # Create a new MITRE_ATTACK_Platforms object
                mitre_attack_platforms = MITRE_ATTACK_Platforms(
                    UUID = str(uuid4()),
                    Name = platform,
                )

                # Add the MITRE_ATTACK_Platforms object to the final export
                final_export['MITRE_ATTACK_Platforms'].append(mitre_attack_platforms.__dict__)
                mitre_attack_platforms_UUID = mitre_attack_platforms.UUID

            else:
                # Get the UUID of the existing platform
                mitre_attack_platforms_UUID = [d for d in final_export['MITRE_ATTACK_Platforms'] if d['Name'] == platform][0]['UUID']

            # Create a new MITRE_Malware_Platforms object
            mitre_malware_platforms = MITRE_Malware_Platforms(
                Malware_ID = mitre_malware.UUID,
                Platform_ID = mitre_attack_platforms_UUID
            )

            # Add the MITRE_Malware_Platforms object to the final export
            final_export['MITRE_Malware_Platforms'].append(mitre_malware_platforms.__dict__)



####################################################
# MITRE_TACTIC & MITRE_Tactic_References
####################################################

# Iterate through the tactics directory
for filename in os.listdir('x-mitre-tactic'):
    # Read in the json file
    with open('x-mitre-tactic/' + filename) as f:
        data = json.load(f)

    # Create a new MITRE_TACTIC object
    mitre_tactic = MITRE_TACTIC(
        UUID = data['objects'][0]['id'].replace('x-mitre-tactic--', ''),
        Name = data['objects'][0]['name'],
        Description = data['objects'][0]['description'],
        Shortname= data['objects'][0]['x_mitre_shortname'],
    )

    # Add the MITRE_TACTIC object to the final export
    final_export['MITRE_TACTIC'].append(mitre_tactic.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for reference in data['objects'][0]['external_references']:
            # Check that a description exists if not make it blank
            if 'description' in reference:
                description = reference['description']
            else:
                description = ''

            if 'url' in reference:
                url = reference['url']
            else:
                url = ''

            mitre_tactic_reference = MITRE_Tactic_References(
                Source_Name = reference['source_name'],
                URL = url,
                Description = description,
                Tactic_ID = mitre_tactic.UUID
            )

            # Add the MITRE_Tactic_References object to the final export
            final_export['MITRE_Tactic_References'].append(mitre_tactic_reference.__dict__)




############################################################
# MITRE_GROUP & MITRE_Group_Aliases & MITRE_Group_References
############################################################
# Iterate through the intrustion-set directory
for filename in os.listdir('intrusion-set'):
    # Read in the json file
    with open('intrusion-set/' + filename) as f:
        data = json.load(f)

    # Create a new MITRE_Group object
    # Check if the group is depreciated
    if 'x_mitre_deprecated' in data['objects'][0]:
        depreciated = data['objects'][0]['x_mitre_deprecated']
    else:
        depreciated = 0

    # Check if group has a description
    if 'description' in data['objects'][0]:
        description = data['objects'][0]['description']
    else:
        description = ''

    # Check if group has a revoked status
    if 'revoked' in data['objects'][0]:
        revoked = data['objects'][0]['revoked']
    else:
        revoked = 0

    mitre_group = MITRE_Group(
        UUID = data['objects'][0]['id'].replace('intrusion-set--', ''),
        Name = data['objects'][0]['name'],
        Description = description,
        Depreciated = depreciated,
        Revoked = revoked,
        Version_Number= data['objects'][0]['x_mitre_version']
    )

    # Add the MITRE_Group object to the final export
    final_export['MITRE_Group'].append(mitre_group.__dict__)


    # Aliases if they exist
    if 'aliases' in data['objects'][0]:
        for alias in data['objects'][0]['aliases']:
            # Create a new MITRE_Group_Aliases object
            mitre_group_aliases = MITRE_Group_Aliases(
                Name = alias,
                Group_ID = mitre_group.UUID
            )

            # Add the MITRE_Group_Aliases object to the final export
            final_export['MITRE_Group_Aliases'].append(mitre_group_aliases.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for reference in data['objects'][0]['external_references']:
            # Check that a description exists if not make it blank
            if 'description' in reference:
                description = reference['description']
            else:
                description = ''

            if 'url' in reference:
                url = reference['url']
            else:
                url = ''

            mitre_group_reference = MITRE_Group_References(
                Source_Name = reference['source_name'],
                URL = url,
                Description = description,
                Group_ID = mitre_group.UUID
            )

            # Add the MITRE_Group_References object to the final export
            final_export['MITRE_Group_References'].append(mitre_group_reference.__dict__)



####################################################
# MITRE_Mitigation & MITRE_Mitigation_References
####################################################
# Iterate through the course-of-action directory
for filename in os.listdir('course-of-action'):
    # Read in the json file
    with open('course-of-action/' + filename) as f:
        data = json.load(f)

    # Create a new MITRE_Mitigation object
    # Check if the mitigation is depreciated
    if 'x_mitre_deprecated' in data['objects'][0]:
        depreciated = data['objects'][0]['x_mitre_deprecated']
    else:
        depreciated = 0

    # Check if has modified
    if 'modified' in data['objects'][0]:
        modified = data['objects'][0]['modified']
    else:
        modified = None

    mitre_mitigation = MITRE_Mitigation(
        UUID = data['objects'][0]['id'].replace('course-of-action--', ''),
        Name = data['objects'][0]['name'],
        Description = data['objects'][0]['description'],
        Version = data['objects'][0]['x_mitre_version'],
        Depreciated = depreciated,
        Created_Date = data['objects'][0]['created'],
        Modified_Date= modified
    )

    # Add the MITRE_Mitigation object to the final export
    final_export['MITRE_Mitigation'].append(mitre_mitigation.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for reference in data['objects'][0]['external_references']:
            # Check that a description exists if not make it blank
            if 'description' in reference:
                description = reference['description']
            else:
                description = ''

            if 'url' in reference:
                url = reference['url']
            else:
                url = ''

            mitre_mitigation_reference = MITRE_Mitigation_References(
                Source_Name = reference['source_name'],
                URL = url,
                Description = description,
                Mitigation_ID = mitre_mitigation.UUID
            )

            # Add the MITRE_Mitigation_References object to the final export
            final_export['MITRE_Mitigation_References'].append(mitre_mitigation_reference.__dict__)




#############################################################
# MITRE_ATTACK_Campaign & MITRE_ATTACK_Campaign_References &
# MITRE_ATTACK_Campaign_Aliases
#############################################################
# Iterate through the campaign directory
for filename in os.listdir('campaign'):
    # Read in the json file
    with open('campaign/' + filename) as f:
        data = json.load(f)

    # Create a new MITRE_ATTACK_Campaign object
    # Check if the campaign is depreciated
    if 'x_mitre_deprecated' in data['objects'][0]:
        depreciated = data['objects'][0]['x_mitre_deprecated']
    else:
        depreciated = 0
        
    # Check if first seen
    if 'first_seen' in data['objects'][0]:
        first_seen = data['objects'][0]['first_seen']
    else:
        first_seen = None

    # Check if last seen
    if 'last_seen' in data['objects'][0]:
        last_seen = data['objects'][0]['last_seen']
    else:
        last_seen = None

    mitre_attack_campaign = MITRE_ATTACK_Campaign(
        UUID = data['objects'][0]['id'].replace('campaign--', ''),
        Name = data['objects'][0]['name'],
        Description = data['objects'][0]['description'],
        First_Seen= first_seen,
        Last_Seen = last_seen,
        Created_Date= data['objects'][0]['created'],
        Modified_Date= data['objects'][0]['modified'],
        Revoked = data['objects'][0]['revoked'],
        Depreciated= depreciated,
        Version = data['objects'][0]['x_mitre_version']
    )

    # Add the MITRE_ATTACK_Campaign object to the final export
    final_export['MITRE_ATTACK_Campaign'].append(mitre_attack_campaign.__dict__)

    # Aliases if they exist
    if 'aliases' in data['objects'][0]:
        for alias in data['objects'][0]['aliases']:
            # Create a new MITRE_ATTACK_Campaign_Aliases object
            mitre_attack_campaign_aliases = MITRE_ATTACK_Campaign_Aliases(
                Name = alias,
                Campaign_ID = mitre_attack_campaign.UUID
            )

            # Add the MITRE_ATTACK_Campaign_Aliases object to the final export
            final_export['MITRE_ATTACK_Campaign_Aliases'].append(mitre_attack_campaign_aliases.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for reference in data['objects'][0]['external_references']:
            # Check that a description exists if not make it blank
            if 'description' in reference:
                description = reference['description']
            else:
                description = ''

            if 'url' in reference:
                url = reference['url']
            else:
                url = ''

            mitre_attack_campaign_reference = MITRE_ATTACK_Campaign_References(
                Source_Name = reference['source_name'],
                URL = url,
                Description = description,
                Campaign_ID = mitre_attack_campaign.UUID
            )

            # Add the MITRE_ATTACK_Campaign_References object to the final export
            final_export['MITRE_ATTACK_Campaign_References'].append(mitre_attack_campaign_reference.__dict__)

            







# # Iterate through the relationships directory
# for filename in os.listdir('relationship'):
#     # Read in the json file
#     with open('relationship/' + filename) as f:
#         data = json.load(f)

#     # Check if the source_ref is malware and the target_ref is malware
#     if data['objects'][0]['source_ref'].startswith('malware--') and data['objects'][0]['target_ref'].startswith('malware--'):
#         # Update the malware object that's UUID is the source_ref
#         # So that the Superseded_By field is the UUID in the target_ref
#         # Update the malware in the final export
#         for malware in final_export['MITRE_Malware']:
#             if malware['UUID'] == data['objects'][0]['source_ref'].replace('malware--', ''):
#                 malware['Superseded_By'] = data['objects'][0]['target_ref'].replace('malware--', '')



        

            
    



# Write the final export to a json file
with open('final_export.json', 'w') as outfile:
    json.dump(final_export, outfile, indent=4)




                
# Delete the old database
if os.path.exists('ATTACK_EXPORT.sqlite3'):
    os.remove('ATTACK_EXPORT.sqlite3')

# Create the database
create_database_from_dict('ATTACK_EXPORT.sqlite3', final_export)

