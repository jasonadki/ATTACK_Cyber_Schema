# Cyber Data Schema -- MITRE ATT&CK

The following repository stores a subset of the Cyber Data Schema, specifically, the MITRE ATT&CK Entreprise. (https://attack.mitre.org/)


<br>
<br>


In the Schema there will be two color codings:

- **`MITRE Tables (#FFE5B4)`**
    - These are tables that are unique to the MITRE ATT&CK database and non <i>generic</i> values. Ie, **Groups** and **Techniques**
- **`Reference Tables (#FFD12A)`**
    - These are tables that are commonly chosen values that get used for reference. Ie, **Impact_Types** and **System_Permissions**.<br><br>
     The purpose of these tables are to have unique objects that get references for standardization purposes. For example imagine referencing an interface port as either <i>Universal Serial Bus</i> or <i>USB</i>. Both are refering to the same thing but, thinking ahead for data analytics purposes, a computer/code does not inherently recognize these as the same interface type. This problem only grows exponentially when we consider user-facing applications that have free-form fields which allow typo's. These tables would be maintained by a respective authority who provide periodic updates. 


<br>


# Project Folders
<br>

## Non-Default files
Files and Folders that were created as part of this effort.

- `mapper_run.py`
    - The actual Python code that reads the provide ATT&CK files and transforms them into a Schema representation of JSON and SQLITE3.<br>

- `Schema.py`
    - A class representation of all the `Objects/Attributes` or `Tables/Columns` of the Cyber Data Schema.<br>

- `final_export.json`
    - The `Object/Attribute` representation of MITRE ATT&CK Enterprise in JSON format.<br>

- `ATTACK_EXPORT.sqlite3`
    - The `Table/Column` representation of MITRE ATT&CK Enterprise in Sqlite format.<br>

- `_example_queries`
    - Sql queries used to demonstrate how information can be pulled. These can be associated with Python queries found in https://github.com/mitre-attack/mitreattack-python/tree/master/examples.<br>

- `_SCHEMA`
    - `ATT&CK_Schema.mwb`
        - MySQL Workbench file of the Schema

    - `ATT&CK_Schema.mwb.bak`
        - Backup of the MySQL Workbench file of the Schema? Honestly, idk it just keeps generating whenever I save the file.
        
    - `ATT&CK_Schema.pdf`
        - Entity Relationship Diagram (ERD) of the Data Schema

    - `DataDictionary.html`
        - Data Dictionary of the Data Schema that explains the ERD

    - `table_definitions.json`
        - JSON representation of the data types and formats of the Data Schema

<br>

## Default folders
Files and Folders that came from the MITRE ATT&CK Github page. These were used to generate the Data Schema-compliant exports.
- `attack-pattern`, `campaign`, `course-of-action`, `identity`, `intrusion-set`, `malware`, `marking-definition`, `relationship`, `tool`, `x-mitre-data-component`, `x-mitre-source`, `x-mitre-matrix`, `x-mitre-tactic`, `enterprise-attack.json`