class MITRE_ATTACK_Collection_Layers:
    def __init__(
        self,
        UUID = None,
        Name = None,
    ):
        self.UUID = UUID
        self.Name = Name


class MITRE_Data_Sources_Collection_Layers:
    def __init__(
        self,
        Data_Source_ID = None,
        Layer_ID = None,
    ):
        self.Data_Source_ID = Data_Source_ID
        self.Layer_ID = Layer_ID


class MITRE_Data_Source_Reference:
    def __init__(
        self,
        UUID = None,
        Source_Name = None,
        URL = None,
        Description = None,
        Data_Source_ID = None,
    ):
        self.UUID = UUID
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Data_Source_ID = Data_Source_ID


class MITRE_Data_Sources:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Version = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Version = Version


class MITRE_ATTACK_Platforms:
    def __init__(
        self,
        UUID = None,
        Name = None,
        Is_Operating_System = None,
    ):
        self.UUID = UUID
        self.Name = Name
        self.Is_Operating_System = Is_Operating_System


class MITRE_Data_Sources_Platforms:
    def __init__(
        self,
        Data_Source_ID = None,
        Platform_ID = None,
    ):
        self.Data_Source_ID = Data_Source_ID
        self.Platform_ID = Platform_ID
        

class MITRE_Data_Component:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Version = None,
        Data_Source_ID = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Version = Version
        self.Data_Source_ID = Data_Source_ID


class MITRE_TOOL:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Version = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Version = Version

class MITRE_Tool_References:
    def __init__(
        self,
        Source_Name = None,
        URL = None,
        Description = None,
        Tool_ID = None,
    ):
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Tool_ID = Tool_ID

class MITRE_Tool_Aliases:
    def __init__(
        self,
        Name = None,
        Tool_ID = None,
    ):
        self.Name = Name
        self.Tool_ID = Tool_ID

class MITRE_Tool_Platforms:
    def __init__(
        self,
        Tool_ID = None,
        Platform_ID = None,
    ):
        self.Tool_ID = Tool_ID
        self.Platform_ID = Platform_ID

        
class MITRE_Malware:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Depreciated = None,
        Version_Number = None,
        Superseded_By = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Depreciated = Depreciated
        self.Version_Number = Version_Number
        self.Superseded_By = Superseded_By


class MITRE_Malware_Platforms:
    def __init__(
        self,
        Malware_ID = None,
        Platform_ID = None,
    ):
        self.Malware_ID = Malware_ID
        self.Platform_ID = Platform_ID


class MITRE_MALWARE_Aliases:
    def __init__(
        self,
        Name = None,
        Malware_ID = None,
    ):
        self.Name = Name
        self.Malware_ID = Malware_ID


class MITRE_Malware_References:
    def __init__(
        self,
        Source_Name = None,
        URL = None,
        Description = None,
        Malware_ID = None,
    ):
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Malware_ID = Malware_ID


class MITRE_TACTIC:
    def __init__(
        self,
        UUID = None,
        Name = None,
        Description = None,
        Shortname = None,
    ):
        self.UUID = UUID
        self.Name = Name
        self.Description = Description
        self.Shortname = Shortname


class MITRE_Tactic_References:
    def __init__(
        self,
        Source_Name = None,
        URL = None,
        Description = None,
        Tactic_ID = None,
    ):
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Tactic_ID = Tactic_ID
    

class MITRE_Group:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Revoked = None,
        Depreciated = None,
        Version_Number = None,
        Superseded_By = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Revoked = Revoked
        self.Depreciated = Depreciated
        self.Version_Number = Version_Number
        self.Superseded_By = Superseded_By


class MITRE_Group_Aliases:
    def __init__(
        self,
        Name = None,
        Group_ID = None,
    ):
        self.Name = Name
        self.Group_ID = Group_ID


class MITRE_Group_References:
    def __init__(
        self,
        Source_Name = None,
        URL = None,
        Description = None,
        Group_ID = None,
    ):
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Group_ID = Group_ID


class MITRE_Mitigation:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Depreciated = None,
        Version = None,
        Name = None,
        Created_Date = None,
        Modified_Date = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Depreciated = Depreciated
        self.Version = Version
        self.Name = Name
        self.Created_Date = Created_Date
        self.Modified_Date = Modified_Date


class MITRE_Mitigation_References:
    def __init__(
        self,
        Source_Name = None,
        URL = None,
        Description = None,
        Mitigation_ID = None,
    ):
        self.Source_Name = Source_Name
        self.URL = URL
        self.Description = Description
        self.Mitigation_ID = Mitigation_ID


class MITRE_TECHNIQUE:
    def __init__(
        self,
        UUID = None,
        Description = None,
        Name = None,
        Revoked = None,
        Depreciated = None,
        Detection = None,
        Network_Required = None,
        Remote_Support = None,
        System_Requirements = None,
        Version = None,
        Impact_ID = None,
        Parent_Technique = None,
    ):
        self.UUID = UUID
        self.Description = Description
        self.Name = Name
        self.Revoked = Revoked
        self.Depreciated = Depreciated
        self.Detection = Detection
        self.Network_Required = Network_Required
        self.Remote_Support = Remote_Support
        self.System_Requirements = System_Requirements
        self.Version = Version
        self.Impact_ID = Impact_ID
        self.Parent_Technique = Parent_Technique