-- Used to demonstrate https://github.com/mitre-attack/mitreattack-python/blob/master/examples/get_all_mitigations_mitigating_all_techniques.py
-- Verification at: https://attack.mitre.org/techniques/T1548/

SELECT
    t.Name AS TECHNIQUE_NAME,
    COUNT(m.UUID) AS MITIGATION_COUNT

FROM MITRE_TECHNIQUE t

JOIN MITRE_Mitigation_Technique mt
    ON t.UUID = mt.Technique_ID

JOIN MITRE_Mitigation m
    ON mt.Mitigation_ID = m.UUID

WHERE t.Superseded_By is NULL AND t.Name = 'Abuse Elevation Control Mechanism'