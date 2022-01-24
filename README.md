![2022-01-24 11-34-26 的螢幕擷圖](https://user-images.githubusercontent.com/55401762/150717884-b904ccef-7c0b-4730-a78e-50ebd6605198.png)
# Time Machine
Time machine is a **File Recovery System** that can recover the damaged files attacked by some malware.

In the meantime, it can **remain the change of unattacked files**, instead of recovering the whole system.

## Environment
For the sake of the safety of your computer, We strongly recommend that running our project on the Virtual Machine.
### Ubuntu 20.04 + LVM
You need to enable LVM when installing Ubuntu.

##### Example:
1. Select LVM when installing.
![step1](https://github.com/noidname01/2021-Fall-NMLab-Final/blob/main/pic/step1.png?raw=true)
2. Prepare some other disk space.
3. Create a LVM physical volume
```
pvcreate /dev/<disks\>
```
![step2](https://github.com/noidname01/2021-Fall-NMLab-Final/blob/main/pic/step2.png?raw=true)

4. Add the physical volume to a volume group(default: vgubuntu)
```
vgextend vgubuntu /dev/<disks\>
```
![step3](https://github.com/noidname01/2021-Fall-NMLab-Final/blob/main/pic/step3.png?raw=true)


### Linux Kernel 5.11.0-46 (Important!)
The kernel version can strongly influence the working of BCC and some kernel function, so please be sure you're in correct version.
### LVM
### BCC
Follow the step [here](https://github.com/iovisor/bcc/blob/master/INSTALL.md#ubuntu---source)
## File Structure
```
├── LVM.py              (The api of LVM)
├── filetoplife.py      (The Perf Buffer ver.)
├── filetoplife-ring.py (The Ring Buffer ver.)
```
## Usage

```
python3 filetoplife.py
```
or
```
python3 filetoplife-ring.py
```

The CLI will tell you what to do.

## Note

The main function of the project is based on the [filetop.py](https://github.com/iovisor/bcc/blob/master/tools/filetop.py) and [filelife.py](https://github.com/iovisor/bcc/blob/master/tools/filelife.py) in the BCC tool.
