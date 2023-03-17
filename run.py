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
final_export['MITRE_Tactic'] = []
final_export['MITRE_Tactic_References'] = []
final_export['MITRE_Group'] = []   
final_export['MITRE_Group_Aliases'] = []
final_export['MITRE_Group_References'] = []
final_export['MITRE_Mitigation'] = []
final_export['MITRE_Mitigation_References'] = []
final_export['MITRE_ATTACK_Campaign'] = []
final_export['MITRE_ATTACK_Campaign_References'] = []
final_export['MITRE_ATTACK_Campaign_Aliases'] = []
final_export['MITRE_TECHNIQUE'] = []
final_export['MITRE_ATTACK_Impact_Types'] = []
final_export['System_Permissions'] = []
final_export['MITRE_Technique_Obtained_Permissions'] = []
final_export['MITRE_Technique_Required_Permissions'] = []
final_export['MITRE_ATTACK_Defenses'] = []
final_export['MITRE_Technique_Defense_Bypasses'] = []
final_export['MITRE_Techniques_Platforms'] = []
final_export['MITRE_Technique_Data_Components'] = []
final_export['MITRE_Technique_Tactics'] = []
final_export['MITRE_Technique_References'] = []
final_export['MITRE_External_References'] = []




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

    # References
    for external_reference in data['objects'][0]['external_references']:
        if 'description' in external_reference:
            description = external_reference['description']
        else:
            description = None

        # Check that a url exists if not make it blank
        if 'url' in external_reference:
            url = external_reference['url']
        else:
            url = None

        # Check that the source_name exists if not make it blank
        if 'source_name' in external_reference:
            source_name = external_reference['source_name']
        else:
            source_name = None

        tempRef = {
            'source_name': source_name,
            'url': url,
            'description': description
        }

        referenceUUID = None


        # Nee to check if the URL or Description already exists in the final export and if not make a new one

        # Check if the URL already exists for a different source in the final export if its not None
        if url is not None:
            if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['URL'] == url:
                        referenceUUID = existingRef['UUID']

                        # Create a new MITRE_Data_Source_Reference object
                        mitre_data_source_reference = MITRE_Data_Source_Reference(
                            Data_Source_ID = mitre_data_sources.UUID,
                            Reference_ID = referenceUUID,
                        )

                        # Add the MITRE_Data_Source_Reference object to the final export
                        final_export['MITRE_Data_Source_Reference'].append(mitre_data_source_reference.__dict__)

                        break

        # Check if the Description already exists for a different source in the final export if its not None
        # But don't if a reference was already found by the URL
        if description is not None and referenceUUID is None:
            if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['Description'] == description:
                        referenceUUID = existingRef['UUID']

                        # Create a new MITRE_Data_Source_Reference object
                        mitre_data_source_reference = MITRE_Data_Source_Reference(
                            Data_Source_ID = mitre_data_sources.UUID,
                            Reference_ID = referenceUUID,
                        )

                        # Add the MITRE_Data_Source_Reference object to the final export
                        final_export['MITRE_Data_Source_Reference'].append(mitre_data_source_reference.__dict__)

                        break

        # If the reference was not found in the final export
        if referenceUUID is None:
            # Create a new MITRE_External_References object
            reference = MITRE_External_References(
                UUID = str(uuid4()),
                Source_Name = source_name,
                URL = url,
                Description = description
            )

            # Add the MITRE_External_References object to the final export
            final_export['MITRE_External_References'].append(reference.__dict__)

            referenceUUID = reference.UUID

            # Create a new MITRE_Data_Source_Reference object
            mitre_data_source_reference = MITRE_Data_Source_Reference(
                Data_Source_ID = mitre_data_sources.UUID,
                Reference_ID = referenceUUID,
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


    # References if they exist
    if 'external_references' in data['objects'][0]:
        for external_reference in data['objects'][0]['external_references']:
            if 'description' in external_reference:
                description = external_reference['description']
            else:
                description = None

            # Check that a url exists if not make it blank
            if 'url' in external_reference:
                url = external_reference['url']
            else:
                url = None

            # Check that the source_name exists if not make it blank
            if 'source_name' in external_reference:
                source_name = external_reference['source_name']
            else:
                source_name = None

            tempRef = {
                'source_name': source_name,
                'url': url,
                'description': description
            }

            referenceUUID = None


            # Nee to check if the URL or Description already exists in the final export and if not make a new one

            # Check if the URL already exists for a different source in the final export if its not None
            if url is not None:
                if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['URL'] == url:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Tool_References object
                            mitre_tool_references = MITRE_Tool_References(
                                Tool_ID = mitre_tool.UUID,
                                Reference_ID = referenceUUID
                            )


                            # Add the MITRE_Tool_References object to the final export
                            final_export['MITRE_Tool_References'].append(mitre_tool_references.__dict__)

            # Check if the Description already exists for a different source in the final export if its not None
            if description is not None and referenceUUID is None:
                if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['Description'] == description:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Tool_References object
                            mitre_tool_references = MITRE_Tool_References(
                                Tool_ID = mitre_tool.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Tool_References object to the final export
                            final_export['MITRE_Tool_References'].append(mitre_tool_references.__dict__)

                            break

            # If the referenceUUID is still None then we need to create a new reference
            # If the reference was not found in the final export
            if referenceUUID is None:
                # Create a new MITRE_External_References object
                reference = MITRE_External_References(
                    UUID = str(uuid4()),
                    Source_Name = source_name,
                    URL = url,
                    Description = description
                )

                # Add the MITRE_External_References object to the final export
                final_export['MITRE_External_References'].append(reference.__dict__)

                referenceUUID = reference.UUID

            # Create a new MITRE_Tool_References object
            mitre_tool_references = MITRE_Tool_References(
                Tool_ID = mitre_tool.UUID,
                Reference_ID = referenceUUID
            )

            # Add the MITRE_Tool_References object to the final export
            final_export['MITRE_Tool_References'].append(mitre_tool_references.__dict__)







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


    
    # References
    for external_reference in data['objects'][0]['external_references']:
        if 'description' in external_reference:
            description = external_reference['description']
        else:
            description = None

        # Check that a url exists if not make it blank
        if 'url' in external_reference:
            url = external_reference['url']
        else:
            url = None

        # Check that the source_name exists if not make it blank
        if 'source_name' in external_reference:
            source_name = external_reference['source_name']
        else:
            source_name = None

        tempRef = {
            'source_name': source_name,
            'url': url,
            'description': description
        }

        referenceUUID = None


        # Nee to check if the URL or Description already exists in the final export and if not make a new one

        # Check if the URL already exists for a different source in the final export if its not None
        if url is not None:
            if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['URL'] == url:
                        referenceUUID = existingRef['UUID']

                        # Create a new MITRE_Malware_References object
                        mitre_malware_references = MITRE_Malware_References(
                            Malware_ID = mitre_malware.UUID,
                            Reference_ID = referenceUUID
                        )

                        # Add the MITRE_Malware_References object to the final export
                        final_export['MITRE_Malware_References'].append(mitre_malware_references.__dict__)

                        break

        # Check if the Description already exists for a different source in the final export if its not None
        # But don't if a reference was already found by the URL
        if description is not None and referenceUUID is None:
            if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['Description'] == description:
                        referenceUUID = existingRef['UUID']

                        # Create a new MITRE_Malware_References object
                        mitre_malware_references = MITRE_Malware_References(
                            Malware_ID = mitre_malware.UUID,
                            Reference_ID = referenceUUID
                        )

                        # Add the MITRE_Malware_References object to the final export
                        final_export['MITRE_Malware_References'].append(mitre_malware_references.__dict__)

                        break

        # If a reference was not found in the final export create a new one
        if referenceUUID is None:
            # Create a new MITRE_External_References object
            mitre_external_references = MITRE_External_References(
                UUID = str(uuid4()),
                Source_Name = source_name,
                URL = url,
                Description = description
            )

            # Add the MITRE_External_References object to the final export
            final_export['MITRE_External_References'].append(mitre_external_references.__dict__)

            # Create a new MITRE_Malware_References object
            mitre_malware_references = MITRE_Malware_References(
                Malware_ID = mitre_malware.UUID,
                Reference_ID = mitre_external_references.UUID
            )

            # Add the MITRE_Malware_References object to the final export
            final_export['MITRE_Malware_References'].append(mitre_malware_references.__dict__)






####################################################
# MITRE_Tactic & MITRE_Tactic_References
####################################################

# Iterate through the tactics directory
for filename in os.listdir('x-mitre-tactic'):
    # Read in the json file
    with open('x-mitre-tactic/' + filename) as f:
        data = json.load(f)

    # Create a new MITRE_Tactic object
    tactic = MITRE_Tactic(
        UUID = data['objects'][0]['id'].replace('x-mitre-tactic--', ''),
        Name = data['objects'][0]['name'],
        Description = data['objects'][0]['description'],
        Shortname= data['objects'][0]['x_mitre_shortname'],
    )

    # Add the MITRE_Tactic object to the final export
    final_export['MITRE_Tactic'].append(tactic.__dict__)

    # References if they exist
    if 'external_references' in data['objects'][0]:
        for external_reference in data['objects'][0]['external_references']:
            if 'description' in external_reference:
                description = external_reference['description']
            else:
                description = None

            # Check that a url exists if not make it blank
            if 'url' in external_reference:
                url = external_reference['url']
            else:
                url = None

            # Check that the source_name exists if not make it blank
            if 'source_name' in external_reference:
                source_name = external_reference['source_name']
            else:
                source_name = None

            tempRef = {
                'source_name': source_name,
                'url': url,
                'description': description
            }

            referenceUUID = None


            # Nee to check if the URL or Description already exists in the final export and if not make a new one

            # Check if the URL already exists for a different source in the final export if its not None
            if url is not None:
                if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['URL'] == url:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Tactic_References object
                            mitre_tactic_references = MITRE_Tactic_References(
                                Tactic_ID = tactic.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Tactic_References object to the final export
                            final_export['MITRE_Tactic_References'].append(mitre_tactic_references.__dict__)

                            break

            # Check if the Description already exists for a different source in the final export if its not None
            # But don't if a reference was already found by the URL
            if description is not None and referenceUUID is None:
                if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['Description'] == description:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Tactic_References object
                            mitre_tactic_references = MITRE_Tactic_References(
                                Tactic_ID = tactic.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Tactic_References object to the final export
                            final_export['MITRE_Tactic_References'].append(mitre_tactic_references.__dict__)

                            break

            # If a reference was not found in the final export create a new one
            if referenceUUID is None:
                # Create a new MITRE_External_References object
                mitre_external_references = MITRE_External_References(
                    UUID = str(uuid4()),
                    Source_Name = source_name,
                    URL = url,
                    Description = description
                )

                # Add the MITRE_External_References object to the final export
                final_export['MITRE_External_References'].append(mitre_external_references.__dict__)

                # Create a new MITRE_Tactic_References object
                mitre_tactic_references = MITRE_Tactic_References(
                    Tactic_ID = tactic.UUID,
                    Reference_ID = mitre_external_references.UUID
                )

                # Add the MITRE_Tactic_References object to the final export
                final_export['MITRE_Tactic_References'].append(mitre_tactic_references.__dict__)




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
        for external_reference in data['objects'][0]['external_references']:
            # Check that the description exists if not make it blank
            if 'description' in external_reference:
                description = external_reference['description']
            else:
                description = None

            # Check that the url exists if not make it blank
            if 'url' in external_reference:
                url = external_reference['url']
            else:
                url = None

            # Check that the source_name exists if not make it blank
            if 'source_name' in external_reference:
                source_name = external_reference['source_name']
            else:
                source_name = None

            tempRef = {
                'source_name': source_name,
                'url': url,
                'description': description
            }

            referenceUUID = None


            # Nee to check if the URL or Description already exists in the final export and if not make a new one

            # Check if the URL already exists for a different source in the final export if its not None
            if url is not None:
                if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['URL'] == url:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Group_References object
                            mitre_group_references = MITRE_Group_References(
                                Group_ID = mitre_group.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Group_References object to the final export
                            final_export['MITRE_Group_References'].append(mitre_group_references.__dict__)

                            break

            # Check if the Description already exists for a different source in the final export if its not None
            # But don't if a reference was already found by the URL
            if description is not None and referenceUUID is None:
                if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['Description'] == description:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Group_References object
                            mitre_group_references = MITRE_Group_References(
                                Group_ID = mitre_group.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Group_References object to the final export
                            final_export['MITRE_Group_References'].append(mitre_group_references.__dict__)

                            break

            # If the reference was not found in the final export create a new one
            if referenceUUID is None:
                # Create a new MITRE_External_References object
                mitre_external_references = MITRE_External_References(
                    Source_Name = source_name,
                    URL = url,
                    Description = description
                )

                # Add the MITRE_External_References object to the final export
                final_export['MITRE_External_References'].append(mitre_external_references.__dict__)

                # Create a new MITRE_Group_References object
                mitre_group_references = MITRE_Group_References(
                    Group_ID = mitre_group.UUID,
                    Reference_ID = mitre_external_references.UUID
                )

                # Add the MITRE_Group_References object to the final export
                final_export['MITRE_Group_References'].append(mitre_group_references.__dict__)



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
        for external_reference in data['objects'][0]['external_references']:
            # Check that the description exists if not make it blank
            if 'description' in external_reference:
                description = external_reference['description']
            else:
                description = None

            # Check that the url exists if not make it blank
            if 'url' in external_reference:
                url = external_reference['url']
            else:
                url = None

            # Check that the source_name exists if not make it blank
            if 'source_name' in external_reference:
                source_name = external_reference['source_name']
            else:
                source_name = None

            tempRef = {
                'source_name': source_name,
                'url': url,
                'description': description
            }

            referenceUUID = None


            # Nee to check if the URL or Description already exists in the final export and if not make a new one

            # Check if the URL already exists for a different source in the final export if its not None
            if url is not None:
                if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['URL'] == url:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Mitigation_References object
                            mitre_mitigation_references = MITRE_Mitigation_References(
                                Mitigation_ID = mitre_mitigation.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Mitigation_References object to the final export
                            final_export['MITRE_Mitigation_References'].append(mitre_mitigation_references.__dict__)

                            break

            # Check if the Description already exists for a different source in the final export if its not None
            # But don't if a reference was already found by the URL
            if description is not None and referenceUUID is None:
                if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['Description'] == description:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_Mitigation_References object
                            mitre_mitigation_references = MITRE_Mitigation_References(
                                Mitigation_ID = mitre_mitigation.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_Mitigation_References object to the final export
                            final_export['MITRE_Mitigation_References'].append(mitre_mitigation_references.__dict__)

                            break

            # If the reference was not found in the final export create a new one
            if referenceUUID is None:
                # Create a new MITRE_External_References object
                mitre_external_references = MITRE_External_References(
                    Source_Name = source_name,
                    URL = url,
                    Description = description
                )

                # Add the MITRE_External_References object to the final export
                final_export['MITRE_External_References'].append(mitre_external_references.__dict__)

                # Create a new MITRE_Mitigation_References object
                mitre_mitigation_references = MITRE_Mitigation_References(
                    Mitigation_ID = mitre_mitigation.UUID,
                    Reference_ID = mitre_external_references.UUID
                )

                # Add the MITRE_Mitigation_References object to the final export
                final_export['MITRE_Mitigation_References'].append(mitre_mitigation_references.__dict__)





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
            # Check that the description exists if not make it blank
            if 'description' in external_reference:
                description = external_reference['description']
            else:
                description = None

            # Check that the url exists if not make it blank
            if 'url' in external_reference:
                url = external_reference['url']
            else:
                url = None

            # Check that the source_name exists if not make it blank
            if 'source_name' in external_reference:
                source_name = external_reference['source_name']
            else:
                source_name = None

            tempRef = {
                'source_name': source_name,
                'url': url,
                'description': description
            }

            referenceUUID = None

            # Check if the URL already exists for a different source in the final export if its not None
            if url is not None:
                if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                    # Get the UUID of the reference found in the final export
                    for existingRef in final_export['MITRE_External_References']:
                        if existingRef['URL'] == url:
                            referenceUUID = existingRef['UUID']

                            # Create a new MITRE_ATTACK_Campaign_References object
                            mitre_attack_campaign_references = MITRE_ATTACK_Campaign_References(
                                Campaign_ID = mitre_attack_campaign.UUID,
                                Reference_ID = referenceUUID
                            )

                            # Add the MITRE_ATTACK_Campaign_References object to the final export
                            final_export['MITRE_ATTACK_Campaign_References'].append(mitre_attack_campaign_references.__dict__)

                            break

        # Check if the Description already exists for a different source in the final export if its not None
        # But don't if a reference was already found by the URL
        if description is not None and referenceUUID is None:
            if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['Description'] == description:
                        referenceUUID = existingRef['UUID']

                        # Create a new MITRE_ATTACK_Campaign_References object
                        mitre_attack_campaign_references = MITRE_ATTACK_Campaign_References(
                            Campaign_ID = mitre_attack_campaign.UUID,
                            Reference_ID = referenceUUID
                        )

                        # Add the MITRE_ATTACK_Campaign_References object to the final export
                        final_export['MITRE_ATTACK_Campaign_References'].append(mitre_attack_campaign_references.__dict__)

                        break

        # If the reference was not found in the final export
        if referenceUUID is None:
            # Create a new MITRE_External_References object
            mitre_external_references = MITRE_External_References(
                UUID = str(uuid4()),
                Source_Name = source_name,
                URL = url,
                Description = description
            )

            # Add the MITRE_External_References object to the final export
            final_export['MITRE_External_References'].append(mitre_external_references.__dict__)

            # Create a new MITRE_ATTACK_Campaign_References object
            mitre_attack_campaign_references = MITRE_ATTACK_Campaign_References(
                Campaign_ID = mitre_attack_campaign.UUID,
                Reference_ID = mitre_external_references.UUID
            )

            # Add the MITRE_ATTACK_Campaign_References object to the final export
            final_export['MITRE_ATTACK_Campaign_References'].append(mitre_attack_campaign_references.__dict__)

                        
            




            


#############################################################
# MITRE_TECHNIQUE & MITRE_ATTACK_Impact_Types &
# System_Permissions & MITRE_Technique_Obtained_Permissions &
# MITRE_Technique_Required_Permissions
#############################################################
# Iterate through the attack-pattern directory
for filename in os.listdir('attack-pattern'):
    # Read in the json file
    with open('attack-pattern/' + filename) as f:
        data = json.load(f)

    

    # Check if the technique is revoked
    if 'revoked' in data['objects'][0]:
        revoked = data['objects'][0]['revoked']
    else:
        revoked = 0

    # Check if the technique is depreciated
    if 'x_mitre_deprecated' in data['objects'][0]:
        depreciated = data['objects'][0]['x_mitre_deprecated']
    else:
        depreciated = 0

    # Check if the technique has a detection field
    if 'x_mitre_detection' in data['objects'][0]:
        detection = data['objects'][0]['x_mitre_detection']
    else:
        detection = ''

    # Check if the technique has a x_mitre_remote_support field
    if 'x_mitre_remote_support' in data['objects'][0]:
        remote_support = data['objects'][0]['x_mitre_remote_support']
    else:
        remote_support = ''

    # Impact Types
    # Check if the technique has a x_mitre_impact_type field
    if 'x_mitre_impact_type' in data['objects'][0]:
        impactTypeName = data['objects'][0]['x_mitre_impact_type'][0]

        # Check if the impact type exists in the final export
        if not any(d['Name'] == impactTypeName for d in final_export['MITRE_ATTACK_Impact_Types']):
            # Create a new MITRE_IMPACT_TYPE object
            impactType = MITRE_ATTACK_Impact_Types(
                UUID = str(uuid4()),
                Name = impactTypeName
            )

            # Add the MITRE_IMPACT_TYPE object to the final export
            final_export['MITRE_ATTACK_Impact_Types'].append(impactType.__dict__)

            impactUUID = impactType.UUID

        else:
            # Get the UUID of the impact type found in the final export
            for impactType in final_export['MITRE_ATTACK_Impact_Types']:
                if impactType['Name'] == impactTypeName:
                    impactUUID = impactType['UUID']

    else:
        impactUUID = None


    # System Requirements
    # Check if the technique has a x_mitre_system_requirements field
    if 'x_mitre_system_requirements' in data['objects'][0]:
        sysRq = data['objects'][0]['x_mitre_system_requirements'][0]
    else:
        sysRq = None




    # Create a new MITRE_TECHNIQUE object
    technique = MITRE_TECHNIQUE(
        UUID = data['objects'][0]['id'].replace('attack-pattern--', ''),
        Name = data['objects'][0]['name'],
        Description = data['objects'][0]['description'],
        Revoked= revoked,
        Depreciated= depreciated,
        Detection = detection,
        Remote_Support = remote_support,
        Version= data['objects'][0]['x_mitre_version'],
        Impact_ID = impactUUID,
        System_Requirements = sysRq
    )

    # Add the MITRE_TECHNIQUE object to the final export
    final_export['MITRE_TECHNIQUE'].append(technique.__dict__)


    # Obtained Permissions
    # Check if the technique has a x_mitre_effective_permissions field
    if 'x_mitre_effective_permissions' in data['objects'][0]:
        for permission in data['objects'][0]['x_mitre_effective_permissions']:
            # Check if the permission exists in the final export
            if not any(d['Name'] == permission for d in final_export['System_Permissions']):
                # Create a new System_Permissions object
                system_permission = System_Permissions(
                    UUID = str(uuid4()),
                    Name = permission
                )

                # Add the System_Permissions object to the final export
                final_export['System_Permissions'].append(system_permission.__dict__)

                permissionUUID = system_permission.UUID

            else:
                # Get the UUID of the permission found in the final export
                for system_permission in final_export['System_Permissions']:
                    if system_permission['Name'] == permission:
                        permissionUUID = system_permission['UUID']

            # Create a new MITRE_Technique_Obtained_Permissions object
            technique_obtained_permission = MITRE_Technique_Obtained_Permissions(
                Technique_ID = technique.UUID,
                Permission_ID = permissionUUID
            )

            # Add the MITRE_Technique_Obtained_Permissions object to the final export
            final_export['MITRE_Technique_Obtained_Permissions'].append(technique_obtained_permission.__dict__)


    # Required Permissions
    # Check if the technique has a x_mitre_permissions_required field
    if 'x_mitre_permissions_required' in data['objects'][0]:
        for permission in data['objects'][0]['x_mitre_permissions_required']:
            # Check if the permission exists in the final export
            if not any(d['Name'] == permission for d in final_export['System_Permissions']):
                # Create a new System_Permissions object
                system_permission = System_Permissions(
                    UUID = str(uuid4()),
                    Name = permission
                )

                # Add the System_Permissions object to the final export
                final_export['System_Permissions'].append(system_permission.__dict__)

                permissionUUID = system_permission.UUID

            else:
                # Get the UUID of the permission found in the final export
                for system_permission in final_export['System_Permissions']:
                    if system_permission['Name'] == permission:
                        permissionUUID = system_permission['UUID']

            # Create a new MITRE_Technique_Required_Permissions object
            technique_required_permission = MITRE_Technique_Required_Permissions(
                Technique_ID = technique.UUID,
                Permission_ID = permissionUUID
            )

            # Add the MITRE_Technique_Required_Permissions object to the final export
            final_export['MITRE_Technique_Required_Permissions'].append(technique_required_permission.__dict__)


    # By passed defenses
    # Check if the technique has a x_mitre_defense_bypassed field
    if 'x_mitre_defense_bypassed' in data['objects'][0]:
        for defense in data['objects'][0]['x_mitre_defense_bypassed']:
            # Check if the defense exists in the final export
            if not any(d['Name'] == defense for d in final_export['MITRE_ATTACK_Defenses']):
                # Create a new MITRE_ATTACK_Defenses object
                defense = MITRE_ATTACK_Defenses(
                    UUID = str(uuid4()),
                    Name = defense
                )

                # Add the MITRE_ATTACK_Defenses object to the final export
                final_export['MITRE_ATTACK_Defenses'].append(defense.__dict__)

                defenseUUID = defense.UUID

            else:
                # Get the UUID of the defense found in the final export
                for defense in final_export['MITRE_ATTACK_Defenses']:
                    if defense['Name'] == defense:
                        defenseUUID = defense['UUID']

            # Create a new MITRE_Technique_Defense_Bypasses object
            technique_by_passed_defense = MITRE_Technique_Defense_Bypasses(
                Technique_ID = technique.UUID,
                Defense_ID = defenseUUID
            )

            # Add the MITRE_Technique_Defense_Bypasses object to the final export
            final_export['MITRE_Technique_Defense_Bypasses'].append(technique_by_passed_defense.__dict__)


    # Platforms
    # Check if the technique has a x_mitre_platforms field
    if 'x_mitre_platforms' in data['objects'][0]:
        for platform in data['objects'][0]['x_mitre_platforms']:
            # Check if the platform exists in the final export
            if not any(d['Name'] == platform for d in final_export['MITRE_ATTACK_Platforms']):
                # Create a new MITRE_ATTACK_Platforms object
                newplatform = MITRE_ATTACK_Platforms(
                    UUID = str(uuid4()),
                    Name = platform
                )

                # Add the MITRE_ATTACK_Platforms object to the final export
                final_export['MITRE_ATTACK_Platforms'].append(newplatform.__dict__)

                platformUUID = newplatform.UUID

            else:
                # Get the UUID of the platform found in the final export
                for plat in final_export['MITRE_ATTACK_Platforms']:
                    if plat['Name'] == platform:
                        platformUUID = plat['UUID']

            # Create a new MITRE_ATTACK_Platforms object
            technique_platform = MITRE_Techniques_Platforms(
                Technique_ID = technique.UUID,
                Platform_ID = platformUUID
            )

            # Add the MITRE_Techniques_Platforms object to the final export
            final_export['MITRE_Techniques_Platforms'].append(technique_platform.__dict__)


    # Technique Data Components
    # Check if the technique has a x_mitre_data_sources field
    if 'x_mitre_data_sources' in data['objects'][0]:
        for data_component in data['objects'][0]['x_mitre_data_sources']:
            # Get the right of the : and remove starting whitespace
            data_component = data_component.split(':')[1].lstrip()
            # Check if the data component exists in the final export
            if not any(d['Name'] == data_component for d in final_export['MITRE_Data_Component']):
                # Create a new MITRE_Data_Component object
                data_component = MITRE_Technique_Data_Components(
                    UUID = str(uuid4()),
                    Name = data_component
                )

                # Add the MITRE_Technique_Data_Components object to the final export
                final_export['MITRE_Technique_Data_Components'].append(data_component.__dict__)

                data_componentUUID = data_component.UUID

            else:
                # Get the UUID of the data component found in the final export
                for dc in final_export['MITRE_Data_Component']:
                    if dc['Name'] == data_component:
                        data_componentUUID = dc['UUID']

            # Create a new MITRE_Technique_Data_Components object
            technique_data_component = MITRE_Technique_Data_Components(
                Technique_ID = technique.UUID,
                Data_Component_ID = data_componentUUID
            )

            # Add the MITRE_Technique_Data_Component object to the final export
            final_export['MITRE_Technique_Data_Components'].append(technique_data_component.__dict__)



    # Tactics
    # Check if the technique has a kill_chain_phases field
    if 'kill_chain_phases' in data['objects'][0]:
        for tactic in data['objects'][0]['kill_chain_phases']:
            tactic = tactic['phase_name']
            # Check if the tactic exists in the final export
            if not any(d['Shortname'] == tactic for d in final_export['MITRE_Tactic']):
                # Create a new MITRE_Tactics object
                tact_new = MITRE_Tactic(
                    UUID = str(uuid4()),
                    Name = tactic
                )

                # Add the MITRE_Tactics object to the final export
                final_export['MITRE_Tactic'].append(tact_new.__dict__)

                tacticUUID = tact_new.UUID

            else:
                # Get the UUID of the tactic found in the final export
                for tac in final_export['MITRE_Tactic']:
                    if tac['Shortname'] == tactic:
                        tacticUUID = tac['UUID']

            # Create a new MITRE_Technique_Tactics object
            technique_tactic = MITRE_Technique_Tactics(
                Technique_ID = technique.UUID,
                Tactic_ID = tacticUUID
            )

            # Add the MITRE_Technique_Tactics object to the final export
            final_export['MITRE_Technique_Tactics'].append(technique_tactic.__dict__)


    # References
    for external_reference in data['objects'][0]['external_references']:
        if 'description' in external_reference:
            description = external_reference['description']
        else:
            description = None

        # Check that a url exists if not make it blank
        if 'url' in external_reference:
            url = external_reference['url']
        else:
            url = None

        # Check that the source_name exists if not make it blank
        if 'source_name' in external_reference:
            source_name = external_reference['source_name']
        else:
            source_name = None

        tempRef = {
            'source_name': source_name,
            'url': url,
            'description': description
        }

        referenceUUID = None


        # Nee to check if the URL or Description already exists in the final export and if not make a new one

        # Check if the URL already exists for a different source in the final export if its not None
        if url is not None:
            if any(d['URL'] == url for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['URL'] == url:
                        referenceUUID = existingRef['UUID']
                        
                        # Create a new MITRE_Technique_References object
                        technique_reference = MITRE_Technique_References(
                            Technique_ID = technique.UUID,
                            Reference_ID = referenceUUID
                        )

                        # Add the MITRE_Technique_References object to the final export
                        final_export['MITRE_Technique_References'].append(technique_reference.__dict__)

                        break

        # Check if the Description already exists for a different source in the final export if its not None
        # But don't if a reference was already found by the URL
        if description is not None and referenceUUID is None:
            if any(d['Description'] == description for d in final_export['MITRE_External_References']):
                # Get the UUID of the reference found in the final export
                for existingRef in final_export['MITRE_External_References']:
                    if existingRef['Description'] == description:
                        referenceUUID = existingRef['UUID']
                        
                        # Create a new MITRE_Technique_References object
                        technique_reference = MITRE_Technique_References(
                            Technique_ID = technique.UUID,
                            Reference_ID = referenceUUID
                        )

                        # Add the MITRE_Technique_References object to the final export
                        final_export['MITRE_Technique_References'].append(technique_reference.__dict__)

                        break

        # If the reference was not found in the final export
        if referenceUUID is None:
            # Create a new MITRE_External_References object
            reference = MITRE_External_References(
                UUID = str(uuid4()),
                Source_Name = source_name,
                URL = url,
                Description = description
            )

            # Add the MITRE_External_References object to the final export
            final_export['MITRE_External_References'].append(reference.__dict__)

            referenceUUID = reference.UUID

            # Create a new MITRE_Technique_References object
            technique_reference = MITRE_Technique_References(
                Technique_ID = technique.UUID,
                Reference_ID = referenceUUID
            )

            # Add the MITRE_Technique_References object to the final export
            final_export['MITRE_Technique_References'].append(technique_reference.__dict__)





































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

