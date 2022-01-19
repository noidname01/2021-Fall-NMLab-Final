import subprocess as sb
import sys
import random
import os
class LVM():
    eng = 'abcdefghijklmnopqrstuvwxyz'
    def __init__(self):
        self.pvs=[]
        self.lvs=[]
        self.hascreated=[]
        self.get_status()

    def get_status(self):
        self.pvs,self.lvs=[],[]
        p = sb.Popen(['pvdisplay'],stdout=sb.PIPE)
        pvs = p.stdout.read().decode('utf-8').split('--- Physical volume ---')
        for i in range(1,len(pvs)):
            pvs[i] = pvs[i].split('\n')
        for pv in pvs[1:]:
            c ={
                'n':f'{pv[1].split()[2]}',
                'vg':f'{pv[2].split()[2]}',
                'PEsize':int(pv[5].split()[2][:-3]),
                'freePE':int(pv[7].split()[2]),
                'totalPE':int(pv[6].split()[2])  
            }
            if pv[4].split()[1]=='yes':
                c['allocatable']=True
            else:
                c['allocatable']=False
            self.pvs.append(c)

        p = sb.Popen(['lvdisplay'],stdout=sb.PIPE)
        lvs = p.stdout.read().decode('utf-8').split('--- Logical volume ---')
        inlist=False
        for i in range(1,len(lvs)):
            lvs[i]=lvs[i].split('\n')
        for lv in lvs[1:]:
            c ={
                'n':f'{lv[2].split()[2]}',
                'p':f'{lv[1].split()[2]}',
                'vg':f'{lv[3].split()[2]}',
                'snapshot':[],
            }
            for l in lv[1:]:
                if l == '  LV snapshot status     source of':
                    inlist=True
                    continue
                elif l == '  LV Status              available':
                    inlist=False
                    break
                if inlist:
                    c['snapshot'].append(tuple(l.split()))
            self.lvs.append(c)
    
    def createSnapshot(self,l,size):
        if len(self.lvs[l]['snapshot']) != 0:
            raise NameError('The Logical Volume already had snapshot.')
        vg = self.lvs[l]['vg']
        avaliable_size = 0
        for pv in self.pvs:
            if pv['vg'] == vg:
                avaliable_size += pv['PEsize']*pv['freePE']
        if size > avaliable_size :
            raise ValueError('Not enough PE size for snapshot.')
        name=''
        for _ in range(7):
            name+= random.choice(LVM.eng)
        p = sb.Popen(
                ['lvcreate','--snapshot','-n',name,
                '--size',f'{size}M',f'{self.lvs[l]["p"]}'],stdout=sb.PIPE
            )
        self.get_status()

    def mountSnapshot(self,l):
        for i in range(len(self.lvs)):
            if i != l:
                if self.lvs[i]['n']==self.lvs[l]['snapshot'][0][0]:
                    snapath=self.lvs[i]['p']
        p = sb.Popen(['mkdir','-p',f'/media/{self.lvs[l]["snapshot"][0][0]}'],stdout=sb.PIPE)
        p.stdout.read()
        p = sb.Popen(
                ['mount','-t','auto',snapath,
                f'/media/{self.lvs[l]["snapshot"][0][0]}'],stdout=sb.PIPE
            )
        p.stdout.read()
        return f'/media/{self.lvs[l]["snapshot"][0][0]}'
   
    def unmountSanpshot(self,l):
        p = sb.Popen(['umount',f'/media/{self.lvs[l]["snapshot"][0][0]}'])
        p.stdout.read()
        p = sb.Popen(['rm','-r',f'/media/{self.lvs[l]["snapshot"][0][0]}'])
        p.stdout.read()
    def removeSnapshot(self,l):
        if len(self.lvs[l]['snapshot']) == 0:
            raise NameError('There is no snapshot for the LV.')
        for i in range(len(self.lvs)):
            if i != l:
                if self.lvs[i]['n']==self.lvs[l]['snapshot'][0][0]:
                    snapath=self.lvs[i]['p']
        p = sb.Popen(['lvremove','-y',snapath])
        self.get_status()

    def __repr__(self) :
        to_print = '\n'
        to_print += '--- Logical Volumns ---\n\n'
        for i,lv in enumerate(self.lvs):
            to_print+=f'{i}: {str(lv)}\n'
        return to_print
    



class FileRe():
    def __init__(self,rt,mount=''):
    
        self.mount = mount[:-1]
        # self.mount = mount # mount path
        self.rt = rt # protected parent folder
        self.files = []
        self.getDir(mount+rt)

    def getDir(self,rt):
        notProtect=set(['/proc','/tmp','/media','/mnt'])
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
            dlist = c[0]['p'].split('/')[3:-1]
            exists_parent_folder = ''
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
            fd = os.stat(c[0]["p"])
            fmode ,fuid,fgid = fd.st_mode,fd.st_uid,fd.st_gid
            os.chmod(c[0]["p"],0o400)
            newpath=exists_parent_folder+'/'+c[0]['n']
            p = sb.Popen(['cp',f'{c[0]["p"]}',f'{exists_parent_folder}'],stdout=sb.PIPE)
            p.stdout.read()
            os.chown(newpath,fuid,fgid)
            os.chmod(newpath,fmode)
        elif select==-1 and not all:
            return c

# a = LVM()
#a.createSnapshot(0,1024)
#a.mountSnapshot(0)
# a.unmountSnapshot(0)
# a.removeSnapshot(0)
# print(a)
# reco = FileRe('/','/media/nsfjhqw/')