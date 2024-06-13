import pandas as pd

class fix:
    def __init__(
        self,
        file_changes:pd.DataFrame
    ):
        self.file_changes = file_changes