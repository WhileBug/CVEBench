import shutil
import os
class CVEFolder:
    def __init__(
        self,
        cve_id:str,
        cve_home_path
    ):
        self.cve_id = cve_id
        self.repo_path = cve_home_path+"/"+cve_id+"/repo"

        self.unit_test_name = cve_id+"-unit_test"
        self.unit_test_path = cve_home_path+"/"+cve_id+"/unit_test"
        self.unit_test_issue_path = cve_home_path + "/" + cve_id + "/unit_test/"+cve_id+"-unit_test.md"

        self.fix_name = None
        self.fix_issue_filename = None
        self.fix_patch_filename = None
        self.fix_traj_filename = None
        self.fix_folder = cve_home_path+"/"+cve_id+"/fix"

    def set_fix_name(self, fix_level):
        self.fix_name=self.cve_id+"-fix-"+str(fix_level)
        self.fix_issue_filename = self.fix_folder+"/"+self.fix_name + ".md"
        self.fix_patch_filename = self.fix_folder + "/" + self.fix_name + ".patch"
        self.fix_traj_filename = self.fix_folder + "/" + self.fix_name + ".traj"

    def get_repo_status(self):
        if os.path.exists(self.repo_path):
            return True
        else:
            return False

    def get_fix_folder_status(self):
        if os.path.exists(self.fix_folder):
            return True
        else:
            os.mkdir(self.fix_folder)
            return False

    def get_fix_status(self, fix_level:int=3):
        self.get_fix_folder_status()
        if os.path.exists(self.fix_folder+"/"+self.cve_id+"-fix-"+str(fix_level)+".patch"):
            return True
        else:
            return False

    def get_unit_test_status(self):
        if os.path.exists(self.unit_test_path):
            if os.path.exists(self.unit_test_path+"/unit_test.patch"):
                return True
            else:
                return False
        else:
            os.mkdir(self.unit_test_path)
            return False