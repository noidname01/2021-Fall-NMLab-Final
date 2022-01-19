import imp
import os
import subprocess as sb
from xml.dom.expatbuilder import FragmentBuilder

class FileRe():
    def __init__(self,rt,mount=''):
        self.mount = mount # mount path
        self.rt = rt # protected parent folder
        self.files = []
        self.getDir(mount+rt)

    def getDir(self,rt):
        notProtect=set(['/proc',])
        try:
            for entry in os.scandir(rt):
                if entry.is_file():
                    d = {
                        'n':f'{str(entry.name).split("/")[-1]}',
                        'p':str(entry.path)
                    }
                    self.files.append(d)
                elif entry.is_dir() and not entry.is_symlink():
                    if str(entry.path) in notProtect:
                        pass
                    else:
                        self.getDir(entry.path)   
        except PermissionError:
            pass

    def r(self,filename,select=-1,all=False):     # Recovery if there is only one file
        c = self.files.copy()                     # fit the query. Otherwise ret a list.
        l = len(filename)
        c = list(filter(lambda x: filename == x['n'][:l],c))
        if len(c) == 1:
            dlist = c[0]['p'].split('/')[:-1]
            exists_parent_folder = self.rt
            for d in dlist:
                if os.path.isdir(exists_parent_folder+'/'+d):
                    exists_parent_folder = exists_parent_folder+'/'+d
                else:
                    exists_parent_folder = exists_parent_folder+'/'+d
                    dd = os.stat(self.mount+exists_parent_folder)
                    os.mkdir(exists_parent_folder)
                    os.chown(exists_parent_folder,dd.st_uid,dd.st_gid)
                    os.chmod(exists_parent_folder,dd.st_mode)
                    break
            fd = os.stat(self.mount+c[0]["p"])
            fmode ,fuid,fgid = fd.st_mode,fd.st_uid,fd.st_gid
            os.chmod(self.mount+c[0]["p"],0o0)
            p = sb.Popen(['cp',f'{self.mount+c[0]["p"]}',f'{c[0]["p"]}'],stdout=sb.PIPE)
            os.chown(c[0]["p"],fuid,fgid)
            os.chmod(c[0]["p"],fmode)
        else:
            return c
