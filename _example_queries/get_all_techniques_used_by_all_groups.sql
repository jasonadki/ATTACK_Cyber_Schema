-- Used to demonstrate https://github.com/mitre-attack/mitreattack-python/blob/master/examples/get_all_techniques_used_by_all_groups.py
-- Verification at: https://attack.mitre.org/groups/G0043/

SELECT
    g.name AS GROUP_NAME,
    COUNT(t.name) AS TECHNIQUES_USED

FROM MITRE_TECHNIQUE t

JOIN MITRE_Group_Technique gt
    ON t.UUID = gt.Technique_ID

JOIN MITRE_GROUP g
    ON gt.Group_ID = g.UUID

WHERE t.Superseded_By is NULL AND g.name = 'Group5'

GROUP BY g.name 

