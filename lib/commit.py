from lib.cve_database import ConnSearcher

class commit:
    def __init__(
        self,
        commit_hash:str,
        conn_searcher:ConnSearcher
    ):
        self.commit_hash = commit_hash
        self.conn_searcher = conn_searcher
        self.file_changes = self.get_file_change()

    def get_file_change(self):
        file_change_records = self.conn_searcher.get_file_change_by_hash(
            hash = self.commit_hash
        )
        file_change_records = file_change_records[['filename', 'file_change_id', 'old_path', 'new_path', 'code_before', 'code_after', 'programming_language']]
        return file_change_records

    def get_method_change(self):
        pass