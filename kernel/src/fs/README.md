# Filesystem and Storage Stack

The fs module is Oreulius's storage layer. It ties together block devices, the virtual filesystem, paging support, persistence hooks, and the RAM-backed storage pieces that other kernel subsystems depend on.

## What It Does

It handles raw block I/O, filesystem access, paging, persistence, watches, and the storage glue that lets the rest of the kernel keep data around in a controlled way.

It exists so storage is managed by one coherent kernel layer instead of being scattered across unrelated code. That makes the state easier to inspect, recover, and secure.


---

## Layered Architecture

The layered architecture means the filesystem is built in separate levels, with each layer handling a different job instead of everything being mixed together. Lower layers deal with storage and raw file access, while higher layers handle things like path lookup, permissions, and kernel-facing filesystem behavior. That separation makes the filesystem easier to understand, easier to control, and safer to use inside the kernel.

---

## Block Device Drivers

### ATA / IDE

The ATA driver implements the classic IDE PIO protocol against the two legacy x86 IDE channels (0x1F0 primary, 0x170 secondary), each with a master and slave position. This driver is the lowest-level block I/O path for physical machines and QEMU `-hda` style disks.

#### Port Map

The ports function as I/O addresses the kernel uses to talk to an IDE and ATA disk controller. While IDE disk controllers are outdated, there are modern drive paths as-well. Currently, there is Virtio_blk for block storage, and VVMe storage. These modern storage dont apply to the file system ports in the same way. 

There are several ports involving the ATA and IDE disk controllers. Here is a what each one is for 

| Port | What its for |
|---|---|
|REG_DATA| reads and writes the sector data |
|REG_ERROR | Reports error message for a failed command |
|RGA_LBA_L0, LBA_MID, LBA_HI | these are responsible for the block addresses being accessed|
|REG_DRIVE_HEAD | selects the drive and the upper part of the address |
|REG_COMMAND | Where the kernel sends the command, and retrieves status |
|REG_ALT_STATUS | checks status without clearing interrupt|
|REG_DEV_CONTROL | used for device control, even for a software reset |

The above ports tells the disk what to do, where to do it, and checks wether it has succeeded. 

#### ATA Channels
There are primary and second channels used on the controller, which is related to the master and slave of the ATA channels. The primary and secondary ports control which ATA channels are on the controller, and the Master and Slave decides which drive is on that channel. 

| channel | Type |
|---|---|
|primary | uses the I/O base 0X1F0, control base 0x3F6, and interrupt line 14 |
|secondary | uses the I/0 base 0x1F0, the control base 0x376, and interrupt line 15 |

The kernel therefore has two places it can talk to the legacy IDE disks, giving each channel its own registers and interrupt line. These are used for attaching disks. 

The primary channel is as the name implies for attaching primary hard drives, the main drive you would be using. and the secondary channel is for secondary hard drives or optical drives. They are not different types of connections, but different bus lanes each to carry one master and one slave device. Which one gets to come and go first is dependent on which bus lane is the primary or the secondary. 


The layered architecture means the filesystem is built in separate levels, with each layer handling a different job instead of everything being mixed together. Lower layers deal with storage and raw file access, while higher layers handle things like path lookup, permissions, and kernel-facing filesystem behavior. That separation makes the filesystem easier to understand, easier to control, and safer to use inside the kernel.


#### How the master and slave modes are selected. 

The controller probes the channel, then identifies which drives are present on that channel. First the controller speaks to the master drive, but when or if no master is present, it will fall back to the slave. So, when a read or write happens the driver selets either the master or the slave drive, sending the drive through a shared channel. 

In essence, the master and slave parts of the controller flow, are just which physical drive on the channel is being addressed. The master can be viewed simply as the primary drive on the cable, and the slave being the second one. 
#### LBA28 vs LBA48 Dispatch

There are currentl two numbering modes within the kernel, LBA28, and LBA48. These are not the only possible storage addressing schemes across the whole kernel, these are just the two modes used for the the ATA/IDE storage driver in the file system layer. Specifically in the ata.rs file. 

Think of it like this:

if its a small addressing mode, then the LBA28 is selected, if it is a large addressing mode, then the LBA48 mode is selected.

These are strategically selected dependning non which one can safely reach the part of a disk being read. 

If thedatapoint is from a modern disk at sector, persee, 500,000,000 or beyond, then that would be too large for the LBA28, and the LBA48 mode would be required. 

LBA28, is used in the boot sector, the partition table, and early filesystem metadata. 

The capacity ceilings of these two modes are as follows:

**LBA28 capacity ceiling:**

$$C_{28} = 2^{28} \times 512 \text{ B} = 128 \text{ GiB}$$

**LBA48 capacity ceiling:**

$$C_{48} = 2^{48} \times 512 \text{ B} = 128 \text{ PiB}$$

These two modes exists simply to make the kernel as resource efficient as possible. 

#### ATAError Variants
There are many variants of ATA errors explaining how a disk operation can fail. NoDrive means the drive is not present. NoLbaSupport means the drive does not support LBA addressing. BufferTooSmall means the buffer is not large enough for the requested sector read or write. OutOfRange means the request goes past the end of the drive. DeviceError(u8) means the drive itself reported an error, and the byte value is the error register. NotInitialised means the channel has not been initialised yet.

heres a table to make things easier

|Error message | Explanation 
|---|---|
| NoDrive | The ATA drive is not present|
| NoLBaSupport | the drive does not support LBA addressing |
| BufferTooSmall | the buffer is not large enough for the read/write action|
|OutOfRange | the request goes beyond the end of the drive |
|DeviceError(u8) | the drive itself is reporting an error, so this means the byte value is the error regiester | 
|NotInitialised | the channel has not been initialized currently| 

#### Global Singletons and Health

The filesystem acts as a global singleton accessor, represened in the code as filesystem(). Whenever anything in the filesystem becomes requested one time, it creates a new service, further requests are then shared under that instance. This refrains from creating a new filesystem each and everytie, allowing the kernel to own the service object deeply. 

Health is similar, but is not a singleton servie object. Instead, its been made to be a kernel-owned service object, that also gets used. The largest diffrence, is it doesnt store it under an instance, it stores it in the persistance and crash logs. 

#### IRQ Shim 

The IRQ Shim is a thin compatibility layer, that calls the primary and secodary layer. These two functions are not responsible for the disk work themselves, but they immediately forward it to the disk IRQ. The ATA layer increments the atomic counter for the right channel. 

The reason the shim exists is to keep old entry points active, while the real state can live inside the ATA driver. 

It's essentially a really elaborate redirection system to keep the old dispatch table stable, bookeeping well within the ATA layer, and avoid duplicating logic creating unnecessary resource overhead. 

#### PCI Storage Enumeration

Unlike linux which is designed for broad hardware compatibility, meaning it enumerates the PCI devices through its own model to expose them to a large general purposed operating space and interface, Oreulius is trying to keep the storage path inside the kernels service layer, and tie access back to capabilities. Discovery in Oreulius is more about controlled exposure. 

The key difference is that Linux uses PCI enumeration to bind drivers to hardware, while Oreulius routes that hardware through kernel-managed services and keeps it under a tighter trusted state.

---

### NVMe 

Now this is where things get a little more modern in the kernel architecture. This is the modern storage interface for high speed flash storage and also uses the PCI above to talk to the drive. 

It is essentially like all NVMe storage layers, but has been tuned so that the storage devce is dicovered, initialized, and then exposed through the file systems capability gated service layer 

It effectively stays inside the kernel-managed storage layer, feeding the filesystem and persistance paths, so that access is still controled through the authority model rather than being broad and far reaching. 

#### Queue Configuration and the Controller Configuration Register

this is the place where the NVMe driver tells the controller how to behave, such as enabling it or changing its state. While the que configuration is where the driver queses command and completion that the NVMe uses to move requests between the kernel and the device. 

The controller register turns on the device and configures it while the queue configuration sets up the lanes the driver uses to send work to the drives to get back the results of the loads. 

This way, each workload will not. be allowed to retrieve raw controller access, and read and writes still safely happen strictly, and sternly, under the kernel-controlled policy. The storage path is completely part of the kernels service surface. 

Each queue submission follows a 64-byte submission protocol. So the driver sends each request in a fixed-size command record instead of using an open-ended message format. That makes the NVMe path predictable and easy to parse. 

Secondly, there are 16-byte queue submission records that help keep the command path simple and structured, which makes it easier to layer the capability checks on top of the storage flow. The submission will queue under the 16-byte submission format if the request is valid and the controller is ready to accept it. The request is only valid when it has the right command format, so that 

| Command | Submission Size |
|---|---|
| Command record | 16 bytes or 64 bytes |
| Read | 64 bytes |
| Write | 64 bytes |
| Identify | 64 bytes |
| Flush | 64 bytes |
| Admin or control command | 64 bytes |
| Simple queue submission record | 16 bytes |

Simple queue submission records for the 16byte protocol can be things like a standard singular requests, such as a read request, a write request, an identify request, an flush request, and a small admin command request. These are just for records that are one packaged storage commands that the controller needs to process as one singular unit. 

#### Admin Opcodes and how 16-byte queues are created

in Oreulius, the Opcodes are used for things like creating and deleting th i/0 queues, idenitifying the controller and namespace, setting controller features, and aborting commands. 


It works by setting up the admin submission and completion queues, then sends the command by filling in the 64-byte submission entry. The controler reads that entry, performs the management task required, and then writes back a 16byte entry. Before moving on it checks the completion status. 

These opcodes act as a control submission plane for the NVMe, and helps with commands like read, write and flush. These 



#### IO Opcode Table
read is read on opcode 02, write, is on opcode 01, and flushes that write back cache and persistant media are on opcode value 00. 

Here is a table to visualize it: 


| Opcode | Constant | Function |
|---|---|---|
| 0x00 | NVME_CMD_FLUSH | Flush |
| 0x01 | NVME_CMD_WRITE | Write sectors |
| 0x02 | NVME_CMD_READ  | Read sectors |
#### Initialisation Sequence

The initialization sequence for the NVMe drive works in this flow:

1. turns on the bus mastering
2. reads the controllers capabilities
3. turns the conroller off it was running previously
4. sets up the admin queues in the way explained in the sections above
5. points the controller at these queues
6. turns the controller back on
7. waits for controller status to be ready
8. asks the drive what it is
9. queues the I/0 reads and writes

this lets the controller move data without the CPU doing any heavy lifting, as optimized as possible, and automated. then the driver checks what hardware supports it, and its been spaced, giving the driver a clean and clear starting point. then controle queues the driver to speak with the harderware to retrieve memory addresses and completion queues. 


Once that happens its ready to accept commands and is considered live. The driver at this point sends a command for the controller and name space to know the size and block size. 




---

### VirtIO-blk 

Oreulis implements for the standard VirtiO device interface on the 1.0 protocol. it follows the older style ransport behaviour under legacy PCI for compatibility. 

You can use this QEMU command prefix to attach a VirtIO block device to QEMU

```
-drive if=virtio
```

The virtio block runs on a split of three rings, the descriptor ring, and available ring, and a used ring alongside a write through block cache. 

heres the scope of each ring 

| Ring | Scope |
|---|---|
| Descriptor ring | Holds the request descriptors for one I/O transaction |
| Available ring | Marks which descriptor chains are ready for the device |
| Used ring | Marks which requests the device has finished |




#### Virtqueue Ring Structures
VirtqDesc is the list of memory chunks the driver wants the device to use for one request. VirtqAvail is the list of requests the driver has made ready for the device to process. VirtqUsed is the list of requests the device has finished and reported back. These three parts form the message system the kernel uses to hand work to the VirtIO block device and get the result back.


Each I/O request is built from three parts: a small header that says what to do and which sector to use, a data buffer that holds the bytes being read or written, and a one-byte status area where the device writes back success or failure.

The driver puts the request into the ready list, updates the queue so the device knows there is work to do, and then tells the device to start. After that, it waits until the device marks the request as finished.

#### Status byte bits

The status byte bit flags the code uses to define wether it accepted the requests submitted, finished it or failed 

|Status byte bits | meaning
|---|---|
|ACKNOWLEDGE=1 | The device saw the request|
|DRIVER=2 | The driver is active|
|DRIVER_OK=4 | The device is ready to use|
|FAILED=0x80| The device failed and reports back an error |

#### Block Cache

The block cache stores recently used disk blocks in memory so the kernel does not have to ask the device for the same block over and over again. When the kernel reads a sector, it checks the cache first. If the block is already there, it can return it immediately. If not, it reads it from the device and stores a copy in the cache for later. When the kernel writes a block, this implementation writes through to the device right away and then updates the cache, so the cached copy stays in sync with storage. It makes repeated disk access faster without letting the kernel lose track of what is actually on the drive.

Currently, there is no shell command in this repo that prints the block-cache state, so it would be a good idea to make an Aarch64 specific command to check the block-cache down the road. 

Its also important to note that while the cache is stored inside the filesystems capability gated security paths, they are not currently encrypted, perhaps tying in encryption from the crypto folder would be a good idea in future dev cycles. 


#### Partition Table Parsing

Partitioning in oreulius is much more explicit than a simple background process. It is a direct, visible step in the kernels storage path rather than a something that is hidden. 

When the kernel read the first sector of a disk, and checks whether it looks like an MBR.  if the last two bytes are 0x55AA, it will treat the sector as a valid parition table and read the four standard MBR partition entries from the table. Each entry gives the partition type, whether it is bootable, and where it starts and how many sectors it covers. 

If the MBR contains for example, a special GPT marker type 0xEE, the kernel will then check for a GPT layout, it reads sector one for a GPT header, and after will chekc for the EF1 part signature. Once it does, it reads the GPT partition entries from the LBA listed in the header. Once it aquires all of those entries it then pulls out the first and last sector and the partition name for up to four partitions. 

If it would be easier to understand it as a flow, heres the breakdown:

1. reads sector 0
2. verify the MBR signatur
3. Parse MBR entries 
4. if GPT is indicated, reads the GPT header
5. PArse the GPT partition entries 


It basically just decides whether it is an MBR partition or a GPT partition and decides accordingly. 

Oreulius treats the partition as something the kernel does directly in the storage layer, then exposes the result back to its own service flow. It immedidately stores the results in structures so the kernel can use it immediately. 

For Aarch64, the boot and runtime code also keeps track of the parsed partitions for the debugging and block access. 

>instead of hiding a partion handling behind a big general purpose stack, Oreulius makes the parsing step a part of the explicit storage path. In a space that is easier to trace, inspect, and analyze. 

the shell commands to show the partitions directly in oreulius are as follows 

show partitions directly:
```
blk-partitions
```
Some related storage commands for partitioning:


show basic information about the active block device:
```
blk-info
```

read data from a block device:
```
blk-read
```
write data to a block device:
```
blk-write
```
run a simple block I/O performance test:
```
blk-bench
```
#### MMIO Variant

The MMIO works because the kernel scans the device tree for VirtIO MMIO devices, it reads the MMIO registers to see what kind of device is present, then it sets up the virtqueue in memory, where it writes the queue and status values back through MMIO registers it notifies the device by writing to the queue-notifu register. One its wrtten via the queue-notify register, it waits for the device to update the used queue and finish the request. 

In the code, for block storage heres what happens on the path

|Code | what it does|
|---|---|
|virtio_mmio_probe_all() | discovers the device|
|virtio_mmio_bringup_one() | Initializes the device |
| virtio_blk_submit_sync() | Builds the request in memory |

Then the driver writes queue state through the MMIO, and completes the requests, so the driver can read the status back. 

MMIO is NOT a generic abstraction, instead, it is a concrete way the Aarch64 runtime talks to the VirtIO block device through the memory mapped registers instead of the old x86 ports. 

Importantly these are the block-storage functions in the Virtiopaths for reading and writing 

| Block-storage functions | what they're for |
|---|---|
|init_mmio_active |s ets up the active VirtIO MMIO block device |
|read_sector | reads one 512-byte sector |
|write_sector | writes on 512-byte sector|
|read_sectors | this is a function that can read multiple sectors in one call |
| write_sectors | this can write mutiple sectors in one call|

the flow behind these functions is that the init_mmio_Active gets the device ready, read_sector and write_sector is for single block access, whereas the pluralized versions read_sectors and write_sectors are for multi-block access



---

## RAM-Backed Key-Value Filesystem 

The kernel provides a flat, RAM-backed key-value store that can be broken down into 
1. capability-gated access 
2. thermal file profiling 
3. quota enforcement,  
4. structured event logging. 

It is the persistent object store used by the kernel's internal services such as telemetry,a temporal log, and VFS snapshot, it is completely independent of the POSIX-like VFS layer.

This filesystem should come in handy for small, hot, short livef kernel that needs to stay simple and fast. For things such as the capability state, the boot and session metadata, the temporary service records, health snapshots, telemetry buffers, caches, and any config state that should not be treated like a normal file tree. Partly due to security, and partly due to strictor controls. This is because the ram backed file system gives you gewer ways to discover things by path, fewer chances to accidentlaly expose it, simpler access checks, less file syste overhead, and an easier way to keep it scoped within the trusted state. 

Keep in mind its not automatically safer, but it is easier to secure correctly. it fits the design presece of removing security risks from the get-go by making sure important kernel sate shuld stay inside the controlled service layer, and not be outright exposed out of the box needing to be externally managed. 

### `FileKey`


The FileKey is the filesystems internal name for a stored object. It idenitifies a file-like oehct in the filesystem or Ram-backed store. it is used as a lookupkey to find bytes and cna be packed into a small binary form for IPC or capability handling. 

The capability decides wether a caller is allowed to use that filekey, the filekey is just a thing being asked for and should e considered simply a label that a capability uses to access the stored bytes. 


### Thermal File Profiling

Thermo profiling is a unusual thing in this repo that is a algorithim that tracks how odten files are accessed and classidies them as either hot, warm or cold.

when an item is hot, it means it has been accessed a lot, warm means accesssed sometimes and cold means its barely used.

This algorithmic tracking of usage levels sits inside the kernels storage layer and is part of the service model, not just a background stats counter.

it has the ability to influence chache behaviour, storage health reporting, and kernel decisions about active vs inactive data. 


it's not just simply a "file profiling system", it is the kernel keeping tracks of which data is getting used, and then deciding what should stay hot in the memory and what can cool off. 

You can see the trend of efficiency keeps playing along when it comes to the filesystem. that is the ultimate goal is to create a system that is as efficient as possible. 

Currently there is no shell command for oreulius that lets you see the hot/warm/cold status of a filekey, `health` can show the overall thermal profile, and `vfs-health` shows filesystem-level stats. 

For future work, i should really consider adding a `file-temperature <key>` command.

Ive even put in though of letting someone manually set a files temperature, but decided that would be too risky because the temperature is supposed to reflect raw natural usage patterns, and letting someone change that changes the monitoring, would let someone game cache behaviour, bias storage decisison, hide or exxagerate usage, and make the profile overall less trustworthy in a workplace. 

Some better options, would be to make a command that can clear a score, reset the profile, or pin a file for caching, or apply a policy to override that is seperate from the measured temperature. 

Thermal temperature is best as solely left an internal signal, not a user settable one. 

### How files and file metadata in oreulius is special

Files and file metadata in Oreulius are not just passive disk records. The filesystem treats them as part of the security model, so the kernel tracks the file itself, its access history, and how hot or important it is. That means a file can carry metadata like size, timestamps, read and write counts, last access time, and a rolling hot score.

File access is tied to the capability model. A file does not become accessible just because it has a path. The kernel still checks whether the file exists, whether the caller has permission to use it, and whether the access matches the capability attached to that file.

A file path does not mean anyone can open, read, or write the file. It is only the name the kernel uses to refer to it. The path is an address, not permission.

So whats special and whats the point of even writing this? It's this, Oreulius does not treat files as just blobs on a disk, it tracks their access behaviour, classifies it, and ties them into the capability controlled service layer. Storage then becomes not merely storage, but becomes part of the kernels security, telemetry and scheduling system. 

### Filesystem Rights

rights in oreulius are decided based on what capability is attached to the caller. There are 3 different types of capabilities attached to file system callers in the capability system.

| capability | What it decides |
|---|----|
|Rights | what operatings are allowed READ, WRITE, DELETE|
|Key Prefix | what file names each caller is allowed to touch|
|Quota | how much data the caller is allowed to use|

A caller thus is only accessed if all of those line up, so the capability includes the right operation, the file key mathces the allowed prefix if one is set, and the request stays within quote, if one is set. 

These capabilities match to the following code reference 

| Capability | Code reference |
|---|---|
| Rights | check_permission() |
| Key prefix | check_permission() |
| Quota | check_quota() |

Where, 

1. The check_permission() verifies the right and key scope
2. check_quota() verifies the size and count limits
3. handle_write() and handle_delete() enforces those checks before doing anything


In the file system rights system, attenuating rights measn to shrink the permission set. It takes the current rights, and the requested rights, and keeps the overlap between them, and drops anything extra. 

For example if a capability already has READ | WRITE, you can attenuate it with just read. the important thing to remeber rights can only be reduced not increased. Just a simple safety rule, to make permissions smaller and can never be accidently increased. 

Currently there is no direct command to attenuate the rights of a file. 

The functionality is there however, and can be demonstrated by:
```
cap-test-atten
```

This command creates a from scratch capability, and reduces its rights. 

The planned command im going to develop to individually attenuate rights to a key will work like this.

`attenuate <key> set read=<enable|disable> write=<enable|disable> prefix=<path-prefix> quota=<bytes|files|bytes,files>`

For example, for this command you could set it up like this

`attenuate config/app.json set read=enable write=disable prefix=config/ quota=1048576`

prefix=congif/ means this capability can only touch keys under the config folder, and quota=1048576 means this capability can use up to 1mb. 


### Filesystem Service Deep Dive

The virtual filesystem can enforce the factors explained in the previous section through the Ram-backed filesystem layer, where files are stored in memory, the filesystem service is the thing that maps the label to the data. If the file is on a real block device or VFS layer, they can also be backed by storage, but the key idea is the same . the path is the name not the storage itself. This ties into the filesystem service as the mains storage manager for the kernel, it stores the file in the memory, decides who is allowed to touch them and tracks how the storage is being used. 

Flow of the service functionality
1. the kernel keeps on global filesystem service instance
2. a file is idenitified by a filekey, and is just the name a kernel uses to find it
3. each request comes in with a file system capability
4. the service checks the capability rights, path scope and quota 
5. if the request passes, the service reads, writes deletes or lists the file up for use
6. while doing that, it updates the metadata like size, read/write counts, timestamps, and hotness

So in essence the workflow asks for file access, the kernel checks the capability, the filesystem service checks rights and quota, the storage layer performs the action and then metadata and health stats are updated. 

Because of how the ram-backed file system layers on our virtual file system, it becomes not a dumb filestore, but a kernel service with permission checks, scoped access, quotas, and live storage tracking built right in the core, and influences the functionality from the start, rather than is managed externally. 




#### Module-Level Shims



---

## VFS 

The VFS is a full POSIX-patterned inode-based virtual filesystem with directory trees, hard links, symbolic links, multiple mount backends, an open file descriptor table, inode journalling with fsck, and a capability-gated namespace model. 

### Inode Model
The inode model is what ties the Ram-backed filesystem and the VFS together, by holding the files real information, such as size, permissions, timestamps and where the data is allowed to live. THrough the inode model, it makes links possible, keeps file identity seperate from the file names, and lets the fule system manage metadata more clearly. 

If the path is the label, then the inode is the files actual record underneith that label. The inode gives the kernel a way to treat those stored ojects as a real file record, with identity and not just loose blobs. The inode is one of the mechanisms in code that helps the VFS layer organize and refer to the memory backed files in a strict and consistant secure manner. 





#### InodeKind
There are three different kinds of inodes, file, directory, and symlink. 

Heres a simple table to clarify what each inode does, this is pretty straightforward 


| Variant | Meaning |
|---|---|
| File | Regular file |
| Directory | Directory node |
| Symlink | Symbolic link target string |

### Mount System

The VFS maintains a list of Mount objects, each are tied to a certain prefix, and assigns a contract trait. Each one says what, path it is mounted at, which backend it connects to, and what state that mount is in, as well as what health or usage stat is has collected. This is how the vfs remembers what path is served by that storage system, so that if someone has the path prefix, the vfs uses the mathcing mount to the route to request the right backend. 

These are the following mount systems:
| Mount Method | What its for |
|---|---|
|contract_info() | describes what the mount exposes |
|mkdir() | creates a directory | 
|create_file() | creates a file |
|unlink() | removes a file|
|rmdir() | removes a directory |
|link() | creates a hard link |
|symlink() | creates a symbolic link| 
|readlink() | reads a symlink target |
|open_kind() | describes what kind of handle to open |
|list_entries() | lists directory entries |
|list() | writes a directory listing into the buffer|
|read() | reads the file data |
||write() | writes the file data |
|write_at() | writes at an offset |
| path_size() | reports size for a path |
|stat() | returns file metadata |
|resize() | changes the file size | 
set_times() | updates timestamps |
|sync() | flushes or validates the file state | 

These mount objects are tied to shel aliases if one is currently available. Throughout the continued developing cycles, the missing commands will be decided, and planned to be implemented in a secure way if one currently isnt available. 

| VFS method | Shell command |
|---|---|
| contract_info() | vfs-mounts |
| mkdir() | vfs-mkdir, mkdir |
| create_file() | vfs-write, fs-write |
| unlink() | vfs-delete, rm, fs-delete |
| rmdir() | vfs-rmdir|
| link() | vfs-link |
| symlink() | vfs-symlink |
| readlink() | vfs-readlink |
| open_kind() | vfs-open |
| list_entries() | vfs-ls |
| list() | vfs-ls |
| read()| vfs-read, cat, fs-read |
| write() | vfs-write, fs-write |
| write_at() | none |
| path_size() | none directly |
| stat() | stat |
| resize()| none |
| set_times() | none |
| sync() | none |

### Persistence

The kernel saves important state so it survives across reboots and recovery, in the VFS and filesystem layer, this works like the vfs keeping its state live in memory while the kerne is running, so that when the state changes it can write a snapshot and a journal entry into he kernels ram backed store. on revovery the kernel loads the snapshot first. Then it can replay the journal to rebuild any changes that happened after the snapshot. 

This means the kernel can recover filesystem structure after a reset, keep the mount and inode state consistent, and repaur damage with the fsck_and_repair() command to preserve a health and history data for commands like health-history. 














---

## Paging and Virtual Memory 

the way we implemented this in our kernel is y mappting virtual addresses to physical memory pages, and then keeping those mapping entirely under kernel control, such as the address space the kerenl or workload uses, physical memory, and the translation layer between those two things. our paging system works by creating an address space, mapping the virtual pages to the phsycial pages, and then unmapping when they are no longer necessary, this way it can translate back a virtual address to the physcal one for easier debugging. 

the architectire layer owns the MMU specific parts, the memory module tracks the physical frames, the VFS and runtime code use paging for things like JIT memory, user-mode memory, and temporal mappings. the kernel then uses capability and safety checks around those memory operations instead of exposing raw memory access to workloads. Essentially in oreulius, we turned paging into a security layer. 

If you would like to see a demo on how it works you can use the shell command 

```
paging-test
```
this command maps a test virtual page and verifies the translation and unmaps it again. 

Production paging commands are still in the works, the commands in the works will be in order to expose a real, controlled paging operation that the kernel would need at runtime. It will need to do these jobs. 

1. show a current mapping for a virtual address
2. map a new page into a process or address space
3. unmap a page
4. mark a page read-only or writable
5. create or inspect a copy on write mapping
6. report whether a page is enabled and healthy 

the commands when made will look something like this:
1. map a phsucal page into the processes virtual address space. 
```
paging-map <pid> <virt_addr> <phys_addr> <read|write> <user|kernel>
```
2. remove the mapping for a cirtual address in the chosen processes address space
```
paging-unmap <pid> <virt_addr>
```
3. display the current mapping for the slected virtual address
```
paging-show <pid> <virt_addr>
```
4. mark the page at that virtual address as a copy-on-write for the selected process. 
```
paging-cow <pid> <virt_addr>
```

With these commands the caller would be fully able to get the right capabilities they need. target real processes or kernel owned spaces, validate alignment, permission and range before doing anything, and return a clear success or failure result. 



## Constants

### Page Flags and Bitflags
In Oreulius, PageFlags are the small control bits that describe how a memory page is allowed to behave. They tell the kernel whether the page is present, whether it can be written, whether user code can touch it, and whether it has special handling like copy-on-write. That matters because paging is not just about where memory lives, but also about what kinds of access are allowed on that memory.

Bitflags are just a compact way to store multiple yes or no settings in one number. Each bit stands for one property, so the kernel can combine several page properties into a single flag value. For paging, that is useful because a page entry needs to carry both the address and the access rules for that page.

The BitFlag values are best represented under this table:
| BitFlag | what it means |
|---|---|
| Present | The page is mapped |
| writable | this means writes are allowed |
| UserAccessible | UserMode can access it |
| CopyOnWrite | the page is shared untilthe first write | 
| Dirty | The page has been written already |
| Accessed | the page has been touched | 
| Allocated | the page is reserved in the kernels paging logic | 

Some commands in future dev cycles will be useful to use these flags for inspection.

These commands currently exist: 
|current commands | What it does |
|---|---|
|paging-test | paging demo and self test |
|cow-test | the x86 copy-on-write self test |
| health | paging snapshot as part of the system health profile |

What commands in future use will be:
| Future command | What it will do |
|---|---|
| paging-stats | Show page faults, COW faults, and page copies |
| paging-show <pid> <virt_addr> | Show what a virtual address maps to |
| vm-health | Show whether paging is healthy and consistent |
> The commands below are included for reference in other parts of this doc. But are repeated here so the full future command set is easy to see in one place. 

### PageDirEntry and PageTableEntry
PageDirEntry and PageTableEntry are low level records the kernel uses to describe how the virtual memory is mapped. 

1. PageDirEntry points to a page table
2. PageTableEntry points to an actual physical page.

Some useful commands for future dev cycles would be for mapping inspectionm, and if you would like to change a mapping behaviour. 

These commands would thus need to be capability gated, pid scoped, and split into read only versus mutation. 

Future inspection commands
| Future command | What it will do |
|---|---|
| paging-show <pid> <virt_addr> | Show what a virtual address maps to |
| paging-stats | Show page faults, COW faults, and page copies |
| vm-health | Show whether paging is healthy and consistent |

Mutation commands for only trusted callers
| Future command | What it will do |
|---|---|
| paging-map <pid> <virt_addr> <phys_addr> <read|write> <user|kernel> | Map a physical page into a process |
| paging-unmap <pid> <virt_addr> | Remove a mapping from a process |
| paging-cow <pid> <virt_addr> | Mark a page copy-on-write |

Wether a caller is trusted or not is determined by checking capailities and teh callers idenitty not by guessing, 

The kernel will need to ask 

1. does this caller hold the right capability
2. does that capability allow mapping changes or only inspection
3. is the target PID allowed
4. is the address range valid
5. is the caller operating in a trusted runtime path

The code already enforces deterministic trust, but only for file system and service  access right at the moment.  for these future mutation commands, the enforecement code will need to be added through reuse of the capability model, rather than creating a new system

### How does AddressSpace work on the oreulius Kernel? 

The address space in the kernels container is for the processes memory map. It is used to keep track of which virtual address point that the physical pages allocate themselves too. the kernel can therefore isolate one processes memory from another and manage those mappings in the paging accordingly. It acts as another layer in the paging.  It is the layer that tells the kernel where each piece of memory lives for that process.

There are various test commands in place, but not any physical commands as of yet. 

These are the current test commands in place for the address space 

| Address space test command | what it does |
|---|---|
|paging-test | maps a page, checks the translation, tests copy-on-write, then unmaps it. Serves as a demonstration and a test|
|cow-test | runs the x86 copy-on-write self-test |
| test-pf| triggers a on-purpose page fault |
|fork-test | runs the x86_64 fork and cow regression |
| vmtest | runs a virtual memory self test |

Production commands for actually making use of the address space are still currently under development and will be phased out in future releases. 

These commands will look and work like this: 
| Future command | What it will do |
|---|---|
| paging-show <pid> <virt_addr> | Show what a virtual address maps to |
| paging-map <pid> <virt_addr> <phys_addr> <read|write> <user|kernel> | Create a mapping |
| paging-unmap <pid> <virt_addr> | Remove a mapping |
| paging-cow <pid> <virt_addr> | Mark a page copy-on-write |
| paging-stats | Show page faults, COW faults, and page copies |
| vm-space <pid> | Show the current address-space layout |
| vm-health | Show whether paging is healthy and consistent |


#### Construction Variants
Construction variants are the ways the kernel can create an address space. Such as creating a fresh empty address space, clone an existing one for a new process, create copy-on-write versions for fork, and build a special snadbox or JIt-oriented address space. 

These are the various construction variants and their purposed functionality: 

| Construction variant | Functionality |
|---|---|
| Fresh creation | Gives the process a new clean memory map |
| Clone | Copies an existing map so a new process starts with the same structure |
| Copy-on-write clone | Shares pages first, then makes private copies only when one side writes |
| Special-purpose construction | Sets up memory with extra rules for things like JIT code or kernel-controlled user memory |

There arent any production commands as of yet in the kernel for these aspects either, they are to be made in future dev cycles and planned accordingly to security, architecture alignment, and breadth of capability. 

These future commands will look something like:
| Future variant command | Future use case |
|---|---|
| vm-space-create | Create a fresh address space for a new process |
| vm-space-clone | Copy an existing address space for a new process |
| vm-space-cow | Create a shared copy-on-write address space for fork |
| vm-space-sandbox | Create a restricted address space for a JIT or isolated workload |


#### Copy-On-Write Forking

Copy-on-write forking lets the kernel create a new process without copying every memory page right away. The parent and child start out sharing the same pages, and the kernel only makes a private copy when one of them writes to shared memory. That keeps process creation fast and efficient while still preserving isolation between the two processes.

Some useful ones for this would be
| Production Command | Functionality | 
|---|---|
| cow-fork | mark a page as copy-on-write/create a forked process using copy-on-write |
|paging-stats | confirm if COW faults and page copies are infact happening |

Ways to use paging-cow will be as follows 
| Argument varieties for paging-cow | what it performs |
|---|---|
|cow-fork <pid> <virt_addr> | marks a page copy-on-write |
|cow-fork <pid> <virt_addr> | verify the page is shared or cow-marked |


Clones the address space for process forking:
1. Allocates a new address space.
2. Marks each shared user page as copy-on-write in both the parent and the child. The page `COPY_ON_WRITE` in both the parent and the child the page becomes read-only.
3. Leaves the pages read-only until one side writes to them.
4. When a write happens, the kernel makes a fresh private copy of that page.
5. The writing process gets the new writable page, while the other process keeps the original.

Production commands for the copy on write forking 

#### What stays true after the operation finishes:

the moment after a kernel has finished creating the forked address space, the parent and child start by sharing the same memory, so the kernel does not duplicate everything right away. If either one tries to write to a shared page, the kernel stops that write, makes a private copy of the page for the writer, and then lets the write continue. The other process keeps using the original page. 

#### Key Methods

When actions are performed on the meomory through the AddressSpace, they are called key methods. 

Key methods include but are not limited to the following:

1. mapping a page
2. unmapping a page
3. checking wether a virtual address is mapped
4. converting a virtual address to a physical address
5. cloning an address space
6. handling a copy-on-write fault.

They are the core operations the kernel uses to build, inspect and change a processes memory map. 

aside from the commands paging-test, cow-test and fork-test on x86_64, there is one more test that is currently implemented for testing key methods. that eing vmtest, which runs the architecture side virtual memory self-test. 

For production it would be wise to create commands that target a specific process while requiring explicit permissions that avoid ambient memory access. 

Specifically its important to avoid commands that silently operate on the current process without a PID, or commands that mix inspection and mutation in one action, and commands that expose raw-pagetale internals to the workload. 

The commands that align with such a security architecture are as follows:

| Future key method commands | Action it will perform |
|---|---|
| vm-space-show <pid> | Show the address space layout for a process |
| vm-map <pid> <virt_addr> <phys_addr> <read|write> <user|kernel> | Map a physical page into a process |
| vm-unmap <pid> <virt_addr> | Remove a mapping from a process |
| vm-translate <pid> <virt_addr> | Show which physical page a virtual address points to |
| vm-cow <pid> <virt_addr> | Mark a page copy-on-write |
| vm-clone <pid> | Clone a process address space |
| vm-stats | Show page faults, COW faults, and page copies |
| vm-health | Show whether paging state is consistent |

#### PageFaultErrors 

#### Page Fault Dispatch

Page fault dispatch is how the kernels decision path works when it needs to decide what to do when code touches a memory address that is not currently valid. 


It reads the fault error code, checks wheter the fault looks like a copy-on-write error, and if it is, it hands the fault to. the COW handler. If it is not a a copy-on-write error, it treats it as a deeper fault and stops with detailed fault information. 

It works like this so it protects the memory isolation, and makes copy-on-write work safely so it can prevent bad or unecpected memory access silently corrupting the state. That gives the kernel a controlled response instead of crashing unpredictably. 

Fault error codes are the small set of bits the cpu give the kernel when a page fault happens, so the kernel can tell and read back to you what kind of memory access failed. 

The fault error codes are as follows: 
| Fault error code | What it means |
|---|---|
| Present | The page was mapped, but the access was not allowed |
| Write | The fault happened on a write |
| User | The fault came from user mode |
| Reserved bit | A page table entry had invalid reserved bits set |
| Instruction fetch | The fault happened while fetching an instruction |

#### Global Kernel Address Space
The global kernel address space is the one shared, long lived address space the kernel keeps around for core memory mappings, this is vital for efficiency in order to keep the regular address space less resource intensive for constant usage. 

It remains stable and reused, while the regular one can be switeched, cloned and insepected as part of paging work. 

Essentially the global space acts as an anchor over the workhorse. 

---

## VFS Platform Abstraction 

This is a small and thin abstraction layer in the overall filesystem architecture that allows the VFS to talk to the kernel specific services without being coupled and bound tightly to each other. 

It acts as the bridge between the filesystem code and the rest of the kernel. It allows the VFS to see what process is running, and at what time, removing a direct dependency on the time slice scheduler, or other low level core subsystems. 

This keeps the code across the whole kernel clean, and lets the vfs compile in ways wihtout dragging down the efficiency of the kernel. Plus adds reusability across the platform and the boot modes. 

This isolates the platform from the handling and storage logic, while maintaining compatibility and enhancing both security and efficiency. 


---

## Capability and Rights Model

The fs module implements a two-level capability model that mirrors the IPC capability system.

### RAM-KV Layer 
The RAM-KV (stands for RAM-Key Value) layer is the in memory key-value the kernel needs for fast filesystem style data, that is alot to compartmentalize, so to break that down, heres how that works

1. Each item is stored under a key, such as a path-like name
2. The key points to a file record in memory
3. The file system does a service check of capabilities before letting a caller read, write or delete anything. 

it does not work like a normal disk backed tree system, instead it is managed by a map of names stored to values within the kernel. 

The key is the label, the value is the stored file data, and the service in the file system is the gatekeeper. Good for the internal kernel state, temporary data and fast look ups. 


for the RAM-KV layer, the most useful commadns to develop, will be ones taht allow you to inspect and manage live kernel state without leaking internals everywhere. 

These are wise commands that will increase the usability of the kernel, without diverging in architecture. 
| Future command | What it will do |
|---|---|
| fs-show <key> | Show the value and metadata for one stored item |
| fs-list | List stored keys |
| fs-stats | Show filesystem totals and health |
| fs-delete <key> | Remove a stored item |
| fs-set <key> <data> | Write or update a stored item |
| fs-quota <pid> | Show or set the quota for a process |
| fs-cap <pid> | Show the filesystem capability for a process |
| fs-watch <key> | Watch a key for changes |
| fs-health | Show whether the RAM-KV store is healthy |


### VFS Layer 

The VFS capability model operates on paths:

The code surface of `effective_capability_for_pid` merges directory-scoped and process-scoped capabilities, applying the tightest quota and the intersection of rights, it is the VFS equivalent of the IPC admission pipeline.

The capability model means the kernel checks permissions on the path being accessed, when looking at `effective_capability_for_pid` it showcases the look at the processes capability, look at the directories capability, merfes them, keeps the smaller quota, and keeps only the rights both sides allow. 

It it a admission pipeline where the caller does not get full access automatically, and only what oth path rules and the process rules permit. 

The permissions it checks are:

1. whether the caller can read the path
2. whether the caller can write the path
3. whether the caller can delete or rename the path
4. whether the caller can create new entries under that path
5. whether the caller can list the directory
6. whether the caller can use the request within its quota


---

### Filesystem Watching and IPC Notification

The VFS provides a filesystem event watch system with two delivery mechanisms: polling and IPC channel push.

### Watch API

The kernel watch API is the part of the VFS that lets the kernel notice file systems and report them out. Allowing it to subscribe a path or directory and get notified when file changes happen. this is good for tracking updates, reacting to new files or deletes, and feeding the notifications into IPC or telemetry, and avoiding constant polling. 

its basically there to watch events, and allow the kernel to see if something changed here instead of forcing a caller to keep checking manually, keeping it light and nimble. 

Theres no need for user operation in the Watch-API, however, some diagnostics exist currently that would come in handy, as well as asic filesystem insepction and repair commands. 

The diagnostic commands currently are:
| Current command | What it does |
|---|---|
| vfs-watch | Start watching a path for changes |
| vfs-watch-list | Show active watches |
| vfs-notify | Show recent filesystem notifications |
| vfs-fsck | Inspect and repair VFS structure |
| vfs-health | Show VFS health and mount statistics |
| fs-scrub | Validate and repair filesystem accounting |

however, some potential future development is going to need to be necessary to enhance the quality of these commands. Some of them do currently have arguements some of them dont. 

| Command | Arguments |
|---|---|
| vfs-watch | <path> |
| vfs-unwatch | <id> |
| vfs-watch-list | none |
| vfs-notify | none |
| vfs-fsck | none |
| vfs-health | none |
| fs-scrub | none |

Here are some arguments for future development we are going to need,

Where arguments might be useful for later dev cycles. 

1. vfs-watch-list <path> to filter watches
2. vfs-notify <count> to limit output
3. vfs-health <detail|summary> to choose verbosity
4. fs-scrub <path> to target one subtree instead of the whole store


Not all of them should gain arguments, the rule decided here is that only add arguments if something needs to target something or control the scope of behaviour within the system. 

### VFS Watch
VFS watch (command: vfs-watch) works by registering a watch entry in the recodring events when the watched path changes. 

First, you call the vfs-watch on a path, then the VFS stores the watch in its internal watch list, when something changes under the path, the vfs creates a watch event. Then, the even is added to the notification queue. Where you can check the queued events with vfs-notify.

If an IPC channel is subscribed, the kernel can push events there too, the reciever acknowledges it with the vfs-ipc-ack, which then frees the paths for the next batch. 

It basically just tells the kernel to keep an eye on a filesystem path, so the kernel can report back whenever that path changes. 

### VFS watch events

Events caught under the vfs watch event can include what kind of event change happened, which path changed, and sometimes some extra details about the change.. 

| Kind of event change | What it is |
|---|---|
| Create | A file or directory was added |
| Delete | A file or directory was removed |
| Write | File contents changed |
| Rename | A path changed name or moved |
| Link | A hard link was created or removed |
| Symlink | A symbolic link was created, changed, or removed |
| Metadata change | Permissions, timestamps, size, or similar file info changed |
| Mount change | A mount was added, removed, or updated |

### IPC Push Notifications

Event changes can be subscribed through IPC push notification, to allow the kernel to send filesystem events directly to a channel instead of making a caller poll for them. 

A way to think about it is this, a process can listen to fulesystem changes, and when osmehting in the kernel happens, it pushes the notice to the subscribed IPC channel.

A useful command for future development cycles would be to take advantage of this aspect of the kernel for analaysis sake. 

I think a command along the lines of IPC-listen would be useful in the shell. 

it would give a process a clean way to recieve filesystem or service events, and help it avoid constant polling. It will fit the kernels event drive mode, and make sure wathes and notifications are easier to use operationally. 

What it should do is this:

1. subscribe a process or channel to a specific event source
2. let the caller choose a path, servie or channel scope
3. require capability checks
4. show whether the subscription suceeded or failed 
5. finally, return a subscritption ID so it can be cancelled later. 

it should not listen to everything by default, expose raw kernel internals, bypass the capability model, or become a background snooping tool 

The ipc listen command will be formatted like this:

| Future command | What it does |
|---|---|
| ipc-listen <channel> <source> | Subscribe a channel to a scoped event source |
| ipc-unlisten <id> | Cancel a subscription by ID |
| ipc-listeners | List active IPC listeners |
| ipc-stats <channel> | Show backlog and delivery stats for a channel |
---

## Temporal Persistence

Temporal persistance is deeply integrated in the kernels fule system and storage change processes described above. it measn the kernel does not jsut write data once and forgets about itt. it keeps a record of what changed saves that record and allows it to replay. It is constantly doing this. 

Not only is it useful after a system restart, it is also good for preserving recent writes, replaying backend storage changes, and keeping the kernels view of storage consistant as time goes on. 

Backend writes are done automatically, there arent really any need for any special commands in order to make temporal backend capture happen because the kernel hooks it during VFS writes. 

But in terms of what commands do need to exist, the snapshot, history, rollback and branching are all operational features in the code, and do infact have current existing commands. 

Heres a table to represent these commands that are currently live (though not all perfect in terms of functionality) 

| Command | What it does |
|---|---|
| temporal-write <path> <data> | Write data and record a new version |
| temporal-snapshot <path> | Capture the current state of a path |
| temporal-history <path> | Show the version history for a path |
| temporal-read <path> <version_id> | Read a specific stored version |
| temporal-rollback <path> <version_id> | Restore a path to an older version |
| temporal-branch-create <path> <branch> [from_version] | Create a named branch from a version |
| temporal-branch-list <path> | List branches for a path |
| temporal-branch-checkout <path> <branch> | Switch a path to a branch head |
| temporal-merge <path> <source_branch> [target_branch] [ff-only|ours|theirs|three-way] | Merge one branch into another |
| temporal-stats | Show temporal object statistics |
| temporal-retention [show|set|reset|gc] | View or change retention behavior |


## Diagnostics and Health

We covered alot of high level details on diagnostics and health but here is a deeper dive. 

### Filesystem Health
In oreulius, filesystem health means these crucual things:
1. Files still match their recorded metadata
2. sizes and counts line up
3. mounts are still healthy
4. no unexpected errors have piled up
5. the RAM-KV store and VFS state are still in sync with what the kernel thinks is true, such as if a file still exists, if it still is 128 ytes long, if a mount is active or inactive, a journal and snapshot match, the vfs tree is in a certain shape, or if a file was last written at certain time. 

For 5, syncs can happen when the kernel can write its current state out in a certain way that can be recovered later. 

These syncs specifically happen when the VFS updates its live in memroy state, records a journal entry or snapshot update into the ram-backed fs, on recovery when a snapshot is loaded, and whenever the journal is replayed. It is partially automated and partially manual when other actions are performed. 

For the basic sync mechanism itself, no active commands are necessary or recomended. it happens automatically whenever these example commands are called or performed by the kernel in a operating environemnt. 

1. temporal-write
2. temporal-snapshot
3. temporal-history
4. temporal-rollback
5. vfs-fsck
6. fs-scrub

This should give you a pretty clear picture of how it is a automatic response to both automatic actions the kernel performs, and manual actions that the user performs. 


### File system metrics

file system metrics are the set of numbers the kernel uses to measure how the filesystem is behaving. it is pretty much a scoreboard, that tells you how many files exist, how much data is stored, how many reads and writes have happened. How mahy permission denials occured, and how many mounts are active, how many errors or repairs have been seen.

the closest production commands that exist today that let you operate these features in the code are 

|Command| Action |
|---|---|
| fs-stats | shows filesystem totals and health for the RAM-KV layer|
| vfs-health | shows the VFS health and mount stats |
|health | shows the full system healthand mount stats|

The best fit is fs-stats, there needs to be some arguments developed into this command to take full advantage of the things the code can tell you in terms of metrics. 

These arguments that should be implemented in later development cycles into the kernel as follows 

| Future argument for fs-stats | What it will do |
|---|---|
| none | Show the full filesystem metrics |
| detail | Show a more verbose metrics breakdown |
| health | Focus on filesystem health only |
| mounts | Show mount-related metrics only |
| key <key> | Show metrics for one specific stored item |


## Conclusion
The filesystem in oreulius is entirely memory backed for efficiency. It is capability gated, and health-aware. The vfs connects names to storage backends through mounts. 

Watches, temporal persistance and heath tracking let the kernel observe and recover the state. Paging and address spaces keep memory isolated for workloads

The whole system is built to support secure WASI and rust workloads, this is why its not built like a general pupose-style desktop filesyste,. 


