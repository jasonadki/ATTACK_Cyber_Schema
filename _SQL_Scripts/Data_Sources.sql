SELECT
    ds.Name,
    ds.Description,
    ds.Version,
    ds.Version,
    dsr.Source_Name,
    dsr.URL,
    dsr.Description,
    cl.Name

FROM
    MITRE_Data_Sources ds

INNER JOIN MITRE_Data_Source_Reference dsr
    ON ds.UUID = dsr.Data_Source_ID

INNER JOIN MITRE_Data_Sources_Collection_Layers dscl
    ON ds.UUID = dscl.Data_Source_ID

INNER JOIN MITRE_ATTACK_Collection_Layers cl
    ON dscl.Layer_ID = cl.UUID

WHERE ds.UUID = '1ac0ca69-e07e-4b34-9061-e4588e146c52'

