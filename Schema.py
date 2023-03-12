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

        

