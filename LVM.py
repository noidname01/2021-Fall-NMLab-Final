import imp
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
        p = sb.Popen(
                ['mount','-t','auto',snapath,
                f'/media/{self.lvs[l]["snapshot"][0][0]}'],stdout=sb.PIPE
            )
        return f'/media/{self.lvs[l]["snapshot"][0][0]}'
    def unmountSanpshot(self,l):
        p = sb.Popen(['umount',f'/media/{self.lvs[l]["snapshot"][0][0]}'])

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
    def __init__(self,rt):
        # self.mount = mount # mount path
        self.rt = rt # protected parent folder
        self.files = []
        self.getDir(rt)

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
        c = self.files.copy() # fit the query. Otherwise ret a list.
        l = len(filename)
        c = list(filter(lambda x: filename == x['n'][:l],c))
        if len(c) == 1:
            pass
        else:
            return c


# a = LVM()
#a.createSnapshot(0,1024)
#a.mountSnapshot(0)
# a.unmountSnapshot(0)
# a.removeSnapshot(0)
# print(a)