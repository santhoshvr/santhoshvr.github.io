## :anger: &nbsp;Table of Contents

## :star: &nbsp; Knowledge Sharing

#### Table of Contents

* [terminal](#tool-terminal)
* [mount](#tool-mount)
* [fuser](#tool-fuser)
* [lsof](#tool-lsof)
* [ps](#tool-ps)
* [top](#tool-top)
* [vmstat](#tool-vmstat)
* [iostat](#tool-iostat)
* [strace](#tool-strace)
* [kill](#tool-kill)
* [find](#tool-find)
* [vimdiff](#tool-vimdiff)
* [tail](#tool-tail)
* [cpulimit](#tool-cpulimit)
* [pwdx](#tool-pwdx)
* [tr](#tool-tr)
* [chmod](#tool-chmod)
* [who](#tool-who)
* [last](#tool-last)
* [screen](#tool-screen)
* [script](#tool-script)
* [du](#tool-du)
* [openssl](#tool-openssl)
* [secure-delete](#tool-secure-delete)
* [dd](#tool-dd)
* [gpg](#tool-gpg)
* [system-other](#tool-system-other)
* [curl](#tool-curl)
* [ssh](#tool-ssh)
* [linux-dev](#tool-linux-dev)
* [tcpdump](#tool-tcpdump)
* [nmap](#tool-nmap)
* [netcat](#tool-netcat)
* [netstat](#tool-netstat)
* [rsync](#tool-rsync)
* [host](#tool-host)
* [awk](#tool-awk)
* [sed](#tool-sed)
* [grep](#tool-grep)

#### 1. To delete files . but no recover

```bash
shred -zvu  filename
```

#### 2. To check difference between the two directory

```bash
diff -q ~/trainee_2017/c_programming/ ~/trainee_2017/unix/
```

#### 3. Rename a file at once

```bash
rename -v 's/\.pdf$/\.doc/' .pdf 
file-rename 's/_/ /g' .pdf
```

#### 4. Display the dictionary words

```bash
look word - it is used to get the dictory words.
```

#### 5. tar file with the encryption to create

```bash
tar -czf -  | openssl enc -e -aes256 -out secured.tar.gz 
```

#### 6. Decrypt the tar file from encryption

```bash
openssl enc -d -aes256 -in secured.tar.gz | tar xz -C test
```

#### 7. To run the command every second - shell

```bash
while true ; do echo -ne "`date`\r" ; done 
```

#### 8. To find the duplicate files

```bash
find . ! -empty -type f -exec md5sum {} + | sort | uniq -w32 -dD 
find -type f -exec md5sum '{}' ';' | sort | uniq --all-repeated=separate -w 33
```

```bash
RED Color:
PS1='\[\e[0m\]\[\e]2;\a\e[31;1m\] ${debian_chroot:+($debian_chroot)}\u\[\e[0m\]\[\e[0m\]\[\e]2;\a\e[36;1m\]\w\[\e[0m\]\[\e[0m\]\[\e]2;\a\e[30;1m\]\$\[\e[0m\]'
```

#### 9. Find the last modification time for whole system

```bash
find /home/santhosh/trainee_2017/ -type d -printf '%TY-%Tm-%Td %TT %p\n' | sort -r 
```

#### Find and delete the largest file in the directory

```bash
du -hs  | sort -rh 
```

#### To Find the location of the process file

```bash
lsof -p <pid> -- total info about the process
pwdx <pid>
```

#### To change the color for directory and file types in the terminal

```bash
dircolors 
```

#### High level compression in tar file  using GZIP

```bash
env GZIP=-9 tar cvzf database.tar.gz /home/santhosh/
```

#### To List the limits in the file system

```bash
ulimit -a = To find the limits in the system.
```

#### To create the undeletable file even root also not able to delete

```bash
chattr +i file 
chattr -i file 
```

#### Copy a file to the multiple directory

```bash
echo ./d1 ./d2 | xargs -n 1 cp -v file
```

#### Google Drive access

```bash
sudo add-apt-repository ppa:alessandro-strada/ppa
sudo apt-get update
sudo apt-get install google-drive-ocamlfuse
```

#### Create a file with 100 lines with random values

```bash
cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 100 > /path/to/file
```

#### How to check if running as root in a bash script?

```bash
if (( $EUID != 0 )); then
echo "Please run as root"
exit
fi
```

#### How to exit without saving shell history?

```bash
kill -9 $$
unset HISTFILE && exit
```

#### How to check which ports are listening in my Linux Server?

```bash
lsof -i
ss -l
tcp:
 netstat -tulapn
udp:
 netstat -tupleean

```

#### How does strace connect to an already running process?

```bash

strace -p <PID> - to attach a process to strace.

strace -e trace=read,write -p <PID> - by this you can also trace a process/program for an event, like read and write (in this example). So here it will print all such events that include read and write system calls by the process.

Other such examples
-e trace= network - trace all the network related system calls.
-e trace=signal - trace all signal related system calls.
-e trace=ipc - trace all IPC related system calls.
-e trace=desc - trace all file descriptor related system calls.
-e trace=memory - trace all memory mapping related system calls.
```

#### Font in Italic in terminal

```bash
echo -e "\e[3m Santhosh Italic \e[23m"
```

#### Use SSH behind Squid proxy

```bash
ssh -v root@68.183.83.227 -o "ProxyCommand=nc -X connect -x 192.168.12.10:3128 %h %p"
```

#### Find the largest or bigger files in the system

```bash
find / -xdev -type f -size +100M -exec ls -lhrt {} \;

du -ahx /  | sort -rh | head -30
```

#### Create Bootable OS in pendrive

```bash
  $. lsblk
  $. sudo umount /dev/sd<?><?>  
  $. sudo dd bs=4M if=input.iso of=/dev/sd<?> conv=fdatasync

 (EDIT: If USB drive does not boot (this happened to me), it is because the target is a particular partition on the drive instead of the drive. So the target needs to be /dev/sdc and not dev/sdc <?> For me it was /dev/sdb .)
```

#### Automount network directory

Place the file in the fstab. To check the entry is correct or not. execute the mount -a command.

```bash
192.168.12.10:/home/share /home/share   nfs defaults    0 0
```

#### tar files between dates using find command

```bash
find . -newermt "2020-03-01" ! -newermt "2020-04-01"

find . -newermt "2020-03-01" ! -newermt "2020-04-01" | xargs ls -hrt | xargs tar -czvf IMPSS_Logs_March_2020.tar.gz  1>IMPSS_Logs_March_2020.log &

find . -name '.data' 2>/dev/null | parallel tar  -cjf {1}.tar.bz2 {1}

find . -newermt "2020-05-01" ! -newermt "2020-06-01" -type  f | xargs ls -hrt |  xargs tar -I pigz -cvf IMPSS_Logs_Req_May_2020.tar.gz  1>IMPSS_Logs_Req_May_2020.log &
```

#### Flush the Ip address in machine

```bash
ip addr flush dev eth0
```

#### Multiple machine through firewall

```bash

Just confirmed this worked with some VMs:

[A]$ ssh -tt -v -L8888:localhost:8157 user@B ssh -t -D 8157 user@C

From A, you open up a port forward tunnel from 8888 locally to 8157 on B -L8888:localhost:8157. Once you've established a connection to B, the remote command ssh -t -D 8157 user@C is run, which provides your SOCKS proxy through C. From what I've read, '-t' seems to be required, though I still have to figure out why.

Note, this is one command on the first host which invokes ssh twice, from A->B and from B->C. You could also break this into separate commands, as described below.

Bonus: for chaining three proxies...

Ie A->B->C->D->Internet

[hostA]$ ssh -2 -C -D 55557 -L 55556:127.0.0.1:55556 -L 55555:127.0.0.1:55555 user@B
[hostB]$ ssh -2 -C -D 55556 -L 55555:127.0.0.1:55555 user@C
[hostC]$ ssh -2 -C -D 55555 user@D

Note that for each hop, you need an additional matching forwarder -L on the previous hosts in the chain.

References:

    ssh tunnel via multiple hops
    This posting shows how to chain an arbitrary number of proxies: http://sophiedogg.com/ssh-proxy-through-multiple-servers/
    The template for this solution: http://sysextra.blogspot.com/2013/10/multi-hop-ssh-socks-proxy.html
    How can I use SSH with a SOCKS 5 proxy?
    http://www.jethrocarr.com/2013/03/13/ssh-via-socks-proxies/


https://superuser.com/questions/836194/how-to-chain-socks-proxies

ssh -tt -v -L 1081:localhost:1080 -p223 santhosh@122.165.68.50 ssh -t -D 1080 root@103.16.202.174

proxychains ssh root@192.168.12.200
```

#### Utilizing multi core for tar+gzip/bzip compression/decompression

```bash

You can use pigz instead of gzip, which does gzip compression on multiple cores. Instead of using the -z option, you would pipe it through pigz:

tar cf - paths-to-archive | pigz > archive.tar.gz

By default, pigz uses the number of available cores, or eight if it could not query that. You can ask for more with -p n, e.g. -p 32. pigz has the same options as gzip, so you can request better compression with -9. E.g.

tar cf - paths-to-archive | pigz -9 -p 32 > archive.tar.gz

-rw------- 1 root root  24G Mar  5 12:18 mlog_jul_aug_2017
-rw------- 1 root root 1.4G Jun  2 14:23 mlog_jul_aug_2017.tar.gz

root@DR $ time tar cf - mlog_jul_aug_2017 | pigz > mlog_jul_aug_2017.tar.gz

real 2m25.811s
user 12m3.508s
sys 0m54.628s

```

#### Reverse ssh tunnel

```bash
https://unix.stackexchange.com/questions/46235/how-does-reverse-ssh-tunneling-work 

http://www.augustcouncil.com/%7Etgibson/tutorial/tunneling_tutorial.html

```

#### Best way to copy & restore database

```bash
pg_dump -h 172.16.243.204 -C -U impss impss | bzip2 | ssh -v corpdb@172.16.242.126 "bunzip2 | psql -h 172.16.242.126 -p 5432 -U postgres postgres
```

#### ssh larry to access users machine

```bash
User1: ssh -nNT -R 4444:127.0.0.1:22 user1@122.165.68.50 -p223 -v

User2: ssh -nNT -L 4445:127.0.0.1:4444 user1@122.165.68.50 -p223 -v

ssh user2@127.0.0.1 -p4445
```

#### Mail download from larry

```bash

ssh -L 8888:192.168.12.10:143 root@103.16.202.174 -v

ssh -L 8887:127.0.0.1:8888 santhosh@122.165.68.50
```

#### Openssl RSA encrypt and decrypt command

```bash
For encryption:

openssl rsautl -encrypt -in /path/to/your/file -out /path/to/your/encrypted -pubin -inkey /path/to/your/public_key.pem

For decryption:

openssl rsautl -decrypt -in /path/to/your/encrypted -out /path/where/you/want/your/decrypted.txt -inkey /path/to/your/private_key.pem


Note: If you have this decryption error: RSA_EAY_PRIVATE_DECRYPT:data greater than mod len try this command before decrypt your file: 

cat yourEncryptedFile| base64 -D > yourEncryptedRawFile

https://raymii.org/s/tutorials/Encrypt_and_decrypt_files_to_public_keys_via_the_OpenSSL_Command_Line.html

Learn:

    openssl genrsa: Generates an RSA private keys.
    openssl rsa: Manage RSA private keys (includes generating a public key from it).
    openssl rsautl: Encrypt and decrypt files with RSA keys.
```

#### Delete specific page in pdf file using pdftk

```bash
 for i in pdf ; do pdftk "$i" cat 1 output "trimmed/$i" ; done

```

#### Mount Filesystem through SSH

```bash

sshfs -o allow_other,default_permissions,IdentityFile=~/.ssh/id_rsa root@192.168.12.10:/home/share /home/share

uncomment user_allow_other in /etc/fuse.conf
```

#### Increment number in vim

```bash
Starting with Vim 7.4.754 one can use g Ctrl-a, see :help v_g_CTRL-A

Go to line #4, use Ctrl-v to blockwise select the first character, go down 4 lines, press Shift i, enter 0  (this is 0, followed by Space) and Esc to exit insert mode.

Now use gv to re-select the previously selected area. Press g Ctrl-a to create a sequence.

I start with a 0 here, so I can re-select by gv. If you start with a 1, you need to re-select by hand while omitting the first 1.

Use 2g Ctrl-a to use a step count of 2.
```

#### Make JSON as grepable

```bash
Link: https://github.com/tomnomnom/gron
```

#### record ssh session

```bash
https://www.2daygeek.com/automatically-record-all-users-terminal-sessions-activity-linux-script-command/
```

#### Ipsec VPN configuration

```bash
https://github.com/hwdsl2/setup-ipsec-vpn
L2TP monitoring : 
https://gist.github.com/hwdsl2/855904bfdf0aec6a9cf8d16882acccea
```

#### Send content in pipe curl

```bash
last  | head | curl -X POST -H 'Content-Type: application/json' 'https://chat.googleapis.com/v1/spaces/AAAAuKKC-XI/messages?key=AIzaSyDdI0hCZtE6vySjMm-WEfRq3CPzqKqqsHI&token=RkPPfTH7IJYI5ApPA0NzufMhwWCKGdWOwsTOxYiTCq4%3D' -d  "{\"text\": \"$(</dev/stdin)\"}"
```

#### Convert VirtualBox Fixed HDD to Dynamic

```bash
VBoxManage clonehd [old-VDI] [new-VDI] --variant Standard
VBoxManage clonehd [old-VDI] [new-VDI] --variant Fixed

If you want to expand the capacity of a VDI, you can do so with
VBoxManage modifyhd [VDI] --resize [megabytes] 

Ex. VBoxManage modifyhd Ubuntu12.vdi --resize 30000 (30GB)
```

### Tool: [terminal](https://en.wikipedia.org/wiki/Linux_console)

#### Close shell keeping all subprocess running

```bash
disown -a && exit
```

#### Redirect stdout and stderr each to separate files and print both to the screen

```bash
(some_command 2>&1 1>&3 | tee errorlog ) 3>&1 1>&2 | tee stdoutlog
```

#### Delete all files in a folder that don't match a certain file extension

```bash
rm !(*.foo|*.bar|*.baz)
```

#### Edit a file on a remote host using vim

```bash
vim scp://user@host//etc/fstab
```

#### Convert uppercase files to lowercase files

```bash
rename 'y/A-Z/a-z/' *
```

#### Print a row of characters across the terminal

```bash
printf "%`tput cols`s" | tr ' ' '#'
```

#### Run command(s) after exit session

```bash
cat > /etc/profile << __EOF__
_after_logout() {

  username=$(whoami)

  for _pid in $(ps afx | grep sshd | grep "$username" | awk '{print $1}') ; do

    kill -9 $_pid

  done

}
trap _after_logout EXIT
__EOF__
```

#### Generate a sequence of numbers

```bash
for ((i=1; i<=10; i+=2)) ; do echo $i ; done
# alternative: seq 1 2 10

for ((i=5; i<=10; ++i)) ; do printf '%02d\n' $i ; done
# alternative: seq -w 5 10

for i in {1..10} ; do echo $i ; done
```

#### Simple Bash filewatching

```bash
unset MAIL; export MAILCHECK=1; export MAILPATH='$FILE_TO_WATCH?$MESSAGE'
```

---

### Tool: [mount](https://en.wikipedia.org/wiki/Mount_(Unix))

#### Mount a temporary ram partition

```bash
mount -t tmpfs tmpfs /mnt -o size=64M
```

* `-t` - filesystem type
* `-o` - mount options

#### Remount a filesystem as read/write

```bash
mount -o remount,rw /
```

### Tool: [fuser](https://en.wikipedia.org/wiki/Fuser_(Unix))

#### Show which processes use the files/directories

```bash
fuser /var/log/daemon.log
fuser -v /home/supervisor
```

#### Kills a process that is locking a file

```bash
fuser -ki filename
```

* `-i` - interactive option

#### Kills a process that is locking a file with specific signal

```bash
fuser -k -HUP filename
```

* `--list-signals` - list available signal names

#### Show what PID is listening on specific port

```bash
fuser -v 53/udp
```

#### Show all processes using the named filesystems or block device

```bash
fuser -mv /var/www
```

### Tool: [lsof](https://en.wikipedia.org/wiki/Lsof)

#### Show process that use internet connection at the moment

```bash
lsof -P -i -n
```

#### Show process that use specific port number

```bash
lsof -i tcp:443
```

#### Lists all listening ports together with the PID of the associated process

```bash
lsof -Pan -i tcp -i udp
```

#### List all open ports and their owning executables

```bash
lsof -i -P | grep -i "listen"
```

#### Show all open ports

```bash
lsof -Pnl -i
```

#### Show open ports (LISTEN)

```bash
lsof -Pni4 | grep LISTEN | column -t
```

#### List all files opened by a particular command

```bash
lsof -c "process"
```

#### View user activity per directory

```bash
lsof -u username -a +D /etc
```

#### Show 10 largest open files

```bash
lsof / | \
awk '{ if($7 > 1048576) print $7/1048576 "MB" " " $9 " " $1 }' | \
sort -n -u | tail | column -t
```

#### Show current working directory of a process

```bash
lsof -p <PID> | grep cwd
```

### Tool: [ps](https://en.wikipedia.org/wiki/Ps_(Unix))

#### Show a 4-way scrollable process tree with full details

```bash
ps awwfux | less -S
```

#### Processes per user counter

```bash
ps hax -o user | sort | uniq -c | sort -r
```

### Tool: [find](https://en.wikipedia.org/wiki/Find_(Unix))

#### Find files that have been modified on your system in the past 60 minutes

```bash
find / -mmin 60 -type f
```

#### Find all files larger than 20M

```bash
find / -type f -size +20M
```

#### Find duplicate files (based on MD5 hash)

```bash
find -type f -exec md5sum '{}' ';' | sort | uniq --all-repeated=separate -w 33
```

#### Change permission only for files

```bash
cd /var/www/site && find . -type f -exec chmod 766 {} \;
cd /var/www/site && find . -type f -exec chmod 664 {} +
```

#### Change permission only for directories

```bash
cd /var/www/site && find . -type d -exec chmod g+x {} \;
cd /var/www/site && find . -type d -exec chmod g+rwx {} +
```

#### Find files and directories for specific user/group

```bash
# User:
find . -user <username> -print
find /etc -type f -user <username> -name "*.conf"

# Group:
find /opt -group <group>
find /etc -type f -group <group> -iname "*.conf"
```

#### Find files and directories for all without specific user/group

```bash
# User:
find . \! -user <username> -print

# Group:
find . \! -group <group>
```

#### Looking for files/directories that only have certain permission

```bash
# User
find . -user <username> -perm -u+rw # -rw-r--r--
find /home -user $(whoami) -perm 777 # -rwxrwxrwx

# Group:
find /home -type d -group <group> -perm 755 # -rwxr-xr-x
```

#### Delete older files than 60 days

```bash
find . -type f -mtime +60 -delete
```

#### Recursively remove all empty sub-directories from a directory

```bash
find . -depth  -type d  -empty -exec rmdir {} \;
```

#### How to find all hard links to a file

```bash
find </path/to/dir> -xdev -samefile filename
```

#### Recursively find the latest modified files

```bash
find . -type f -exec stat --format '%Y :%y %n' "{}" \; | sort -nr | cut -d: -f2- | head
```

#### Recursively find/replace of a string with sed

```bash
find . -not -path '*/\.git*' -type f -print0 | xargs -0 sed -i 's/foo/bar/g'
```

#### Recursively find/replace of a string in directories and file names

```bash
find . -depth -name '*test*' -execdir bash -c 'mv -v "$1" "${1//foo/bar}"' _ {} \;
```

#### Recursively find suid executables

```bash
find / \( -perm -4000 -o -perm -2000 \) -type f -exec ls -la {} \;
```

### Tool: [vmstat](https://en.wikipedia.org/wiki/Vmstat)

#### Show current system utilization (fields in kilobytes)

```bash
vmstat 2 20 -t -w
```

* `2` - number of times with a defined time interval (delay)
* `20` - each execution of the command (count)
* `-t` - show timestamp
* `-w` - wide output
* `-S M` - output of the fields in megabytes instead of kilobytes

#### Show current system utilization will get refreshed every 5 seconds

```bash
vmstat 5 -w
```

#### Display report a summary of disk operations

```bash
vmstat -D
```

#### Display report of event counters and memory stats

```bash
vmstat -s
```

#### Display report about kernel objects stored in slab layer cache

```bash
vmstat -m
```

### Tool: [iostat](https://en.wikipedia.org/wiki/Iostat)

#### Show information about the CPU usage, and I/O statistics about all the partitions

```bash
iostat 2 10 -t -m
```

* `2` - number of times with a defined time interval (delay)
* `10` - each execution of the command (count)
* `-t` - show timestamp
* `-m` - fields in megabytes (`-k` - in kilobytes, default)

#### Show information only about the CPU utilization

```bash
iostat 2 10 -t -m -c
```

#### Show information only about the disk utilization

```bash
iostat 2 10 -t -m -d
```

#### Show information only about the LVM utilization

```bash
iostat -N
```

### Tool: [strace](https://en.wikipedia.org/wiki/Strace)

#### Track with child processes

```bash
# 1)
strace -f -p $(pidof glusterfsd)

# 2)
strace -f $(pidof php-fpm | sed 's/\([0-9]*\)/\-p \1/g')
```

#### Track process with 30 seconds limit

```bash
timeout 30 strace $(< /var/run/zabbix/zabbix_agentd.pid)
```

#### Track processes and redirect output to a file

```bash
ps auxw | grep '[a]pache' | awk '{print " -p " $2}' | \
xargs strace -o /tmp/strace-apache-proc.out
```

#### Track with print time spent in each syscall and limit length of print strings

```bash
ps auxw | grep '[i]init_policy' | awk '{print " -p " $2}' | \
xargs strace -f -e trace=network -T -s 10000
```

#### Track the open request of a network port

```bash
strace -f -e trace=bind nc -l 80
```

#### Track the open request of a network port (show TCP/UDP)

```bash
strace -f -e trace=network nc -lu 80
```

___

### Tool: [kill](https://en.wikipedia.org/wiki/Kill_(command))

#### Kill a process running on port

```bash
kill -9 $(lsof -i :<port> | awk '{l=$2} END {print l}')
```

___

### Tool: [vimdiff](http://vimdoc.sourceforge.net/htmldoc/diff.html)

#### Highlight the exact differences, based on characters and words

```bash
vimdiff file1 file2
```

#### Compare two JSON files

```bash
vimdiff <(jq -S . A.json) <(jq -S . B.json)
```

#### Compare Hex dump

```bash
d(){ vimdiff <(f $1) <(f $2);};f(){ hexdump -C $1|cut -d' ' -f3-|tr -s ' ';}; d ~/bin1 ~/bin2
```

___

### Tool: [tail](https://en.wikipedia.org/wiki/Tail_(Unix))

#### Annotate tail -f with timestamps

```bash
tail -f file | while read ; do echo "$(date +%T.%N) $REPLY" ; done
```

#### Analyse an Apache access log for the most common IP addresses

```bash
tail -10000 access_log | awk '{print $1}' | sort | uniq -c | sort -n | tail
```

#### Analyse web server log and show only 5xx http codes

```bash
tail -n 100 -f /path/to/logfile | grep "HTTP/[1-2].[0-1]\" [5]"
```

___

### Tool: [cpulimit](http://cpulimit.sourceforge.net/)

#### Limit the cpu usage of a process

```bash
cpulimit -p pid -l 50
```

___

### Tool: [pwdx](https://www.cyberciti.biz/faq/unix-linux-pwdx-command-examples-usage-syntax/)

#### Show current working directory of a process

```bash
pwdx <pid>
```

___

### Tool: [taskset](https://www.cyberciti.biz/faq/taskset-cpu-affinity-command/)

#### Start a command on only one CPU core

```bash
taskset -c 0 <command>
```

___

### Tool: [tr](https://en.wikipedia.org/wiki/Tr_(Unix))

#### Show directories in the PATH, one per line

```bash
tr : '\n' <<<$PATH
```

___

### Tool: [chmod](https://en.wikipedia.org/wiki/Chmod)

#### Remove executable bit from all files in the current directory

```bash
chmod -R -x+X *
```

#### Restore permission for /bin/chmod

```bash
# 1:
cp /bin/ls chmod.01
cp /bin/chmod chmod.01
./chmod.01 700 file

# 2:
/bin/busybox chmod 0700 /bin/chmod

# 3:
setfacl --set u::rwx,g::---,o::--- /bin/chmod
```

___

### Tool: [who](https://en.wikipedia.org/wiki/Who_(Unix))

#### Find last reboot time

```bash
who -b
```

#### Detect a user sudo-su'd into the current shell

```bash
[[ $(who -m | awk '{ print $1 }') == $(whoami) ]] || echo "You are su-ed to $(whoami)"
```

___

### Tool: [last](https://www.howtoforge.com/linux-last-command/)

#### Was the last reboot a panic?

```bash
(last -x -f $(ls -1t /var/log/wtmp* | head -2 | tail -1); last -x -f /var/log/wtmp) | \
grep -A1 reboot | head -2 | grep -q shutdown && echo "Expected reboot" || echo "Panic reboot"
```

___

### Tool: [screen](https://en.wikipedia.org/wiki/GNU_Screen)

#### Start screen in detached mode

```bash
screen -d -m <command>
```

#### Attach to an existing screen session

```bash
screen -r -d <pid>
```

___

### Tool: [script](https://en.wikipedia.org/wiki/Script_(Unix))

#### Record and replay terminal session

```bash
### Record session
# 1)
script -t 2>~/session.time -a ~/session.log

# 2)
script --timing=session.time session.log

### Replay session
scriptreplay --timing=session.time session.log
```

___

### Tool: [du](https://en.wikipedia.org/wiki/GNU_Screen)

#### Show 20 biggest directories with 'K M G'

```bash
du | \
sort -r -n | \
awk '{split("K M G",v); s=1; while($1>1024){$1/=1024; s++} print int($1)" "v[s]"\t"$2}' | \
head -n 20
```

### Tool: [openssl](https://www.openssl.org/)

#### Testing connection to the remote host

```bash
echo | openssl s_client -connect google.com:443 -showcerts
```

#### Testing connection to the remote host (debug mode)

```bash
echo | openssl s_client -connect google.com:443 -showcerts -tlsextdebug -status
```

#### Testing connection to the remote host (with SNI support)

```bash
echo | openssl s_client -showcerts -servername google.com -connect google.com:443
```

#### Testing connection to the remote host with specific ssl version

```bash
openssl s_client -tls1_2 -connect google.com:443
```

#### Testing connection to the remote host with specific ssl cipher

```bash
openssl s_client -cipher 'AES128-SHA' -connect google.com:443
```

#### Verify 0-RTT

```bash
_host="example.com"

cat > req.in << __EOF__
HEAD / HTTP/1.1
Host: $_host
Connection: close
__EOF__

openssl s_client -connect ${_host}:443 -tls1_3 -sess_out session.pem -ign_eof < req.in
openssl s_client -connect ${_host}:443 -tls1_3 -sess_in session.pem -early_data req.in
```

#### Generate private key without passphrase

```bash
# _len: 2048, 4096
( _fd="private.key" ; _len="2048" ; \
openssl genrsa -out ${_fd} ${_len} )
```

#### Generate private key with passphrase

```bash
# _ciph: des3, aes128, aes256
# _len: 2048, 4096
( _ciph="aes128" ; _fd="private.key" ; _len="2048" ; \
openssl genrsa -${_ciph} -out ${_fd} ${_len} )
```

#### Remove passphrase from private key

```bash
( _fd="private.key" ; _fd_unp="private_unp.key" ; \
openssl rsa -in ${_fd} -out ${_fd_unp} )
```

#### Encrypt existing private key with a passphrase

```bash
# _ciph: des3, aes128, aes256
( _ciph="aes128" ; _fd="private.key" ; _fd_pass="private_pass.key" ; \
openssl rsa -${_ciph} -in ${_fd} -out ${_fd_pass}
```

#### Check private key

```bash
( _fd="private.key" ; \
openssl rsa -check -in ${_fd} )
```

#### Get public key from private key

```bash
( _fd="private.key" ; _fd_pub="public.key" ; \
openssl rsa -pubout -in ${_fd} -out ${_fd_pub} )
```

#### Generate private key and CSR

```bash
( _fd="private.key" ; _fd_csr="request.csr" ; _len="2048" ; \
openssl req -out ${_fd_csr} -new -newkey rsa:${_len} -nodes -keyout ${_fd} )
```

#### Generate CSR

```bash
( _fd="private.key" ; _fd_csr="request.csr" ; \
openssl req -out ${_fd_csr} -new -key ${_fd} )
```

#### Generate CSR (metadata from existing certificate)

  > Where `private.key` is the existing private key. As you can see you do not generate this CSR from your certificate (public key). Also you do not generate the "same" CSR, just a new one to request a new certificate.

```bash
( _fd="private.key" ; _fd_csr="request.csr" ; _fd_crt="cert.crt" ; \
openssl x509 -x509toreq -in ${_fd_crt} -out ${_fd_csr} -signkey ${_fd} )
```

#### Generate CSR with -config param

```bash
( _fd="private.key" ; _fd_csr="request.csr" ; \
openssl req -new -sha256 -key ${_fd} -out ${_fd_csr} \
-config <(
cat << __EOF__
[req]
default_bits        = 2048
default_md          = sha256
prompt              = no
distinguished_name  = dn
req_extensions      = req_ext

[ dn ]
C   = "<two-letter ISO abbreviation for your country>"
ST  = "<state or province where your organisation is legally located>"
L   = "<city where your organisation is legally located>"
O   = "<legal name of your organisation>"
OU  = "<section of the organisation>"
CN  = "<fully qualified domain name>"

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = <fully qualified domain name>
DNS.2 = <next domain>
DNS.3 = <next domain>
__EOF__
))
```

Other values in `[ dn ]`:

```
countryName            = "DE"                     # C=
stateOrProvinceName    = "Hessen"                 # ST=
localityName           = "Keller"                 # L=
postalCode             = "424242"                 # L/postalcode=
postalAddress          = "Keller"                 # L/postaladdress=
streetAddress          = "Crater 1621"            # L/street=
organizationName       = "apfelboymschule"        # O=
organizationalUnitName = "IT Department"          # OU=
commonName             = "example.com"            # CN=
emailAddress           = "webmaster@example.com"  # CN/emailAddress=
```

Example of `oids` (you'll probably also have to make OpenSSL know about the new fields required for EV by adding the following under `[new_oids]`):

```
[req]
...
oid_section         = new_oids

[ new_oids ]
postalCode = 2.5.4.17
streetAddress = 2.5.4.9
```

For more information please look at these great explanations:

* [RFC 5280](https://tools.ietf.org/html/rfc5280)
* [How to create multidomain certificates using config files](https://apfelboymchen.net/gnu/notes/openssl%20multidomain%20with%20config%20files.html)
* [Generate a multi domains certificate using config files](https://gist.github.com/romainnorberg/464758a6620228b977212a3cf20c3e08)
* [Your OpenSSL CSR command is out of date](https://expeditedsecurity.com/blog/openssl-csr-command/)
* [OpenSSL example configuration file](https://www.tbs-certificats.com/openssl-dem-server-cert.cnf)

#### List available EC curves

```bash
openssl ecparam -list_curves
```

#### Print ECDSA private and public keys

```bash
( _fd="private.key" ; \
openssl ec -in ${_fd} -noout -text )

# For x25519 only extracting public key
( _fd="private.key" ; _fd_pub="public.key" ; \
openssl pkey -in ${_fd} -pubout -out ${_fd_pub} )
```

#### Generate ECDSA private key

```bash
# _curve: prime256v1, secp521r1, secp384r1
( _fd="private.key" ; _curve="prime256v1" ; \
openssl ecparam -out ${_fd} -name ${_curve} -genkey )

# _curve: X25519
( _fd="private.key" ; _curve="x25519" ; \
openssl genpkey -algorithm ${_curve} -out ${_fd} )
```

#### Generate private key and CSR (ECC)

```bash
# _curve: prime256v1, secp521r1, secp384r1
( _fd="domain.com.key" ; _fd_csr="domain.com.csr" ; _curve="prime256v1" ; \
openssl ecparam -out ${_fd} -name ${_curve} -genkey ; \
openssl req -new -key ${_fd} -out ${_fd_csr} -sha256 )
```

#### Generate self-signed certificate

```bash
# _len: 2048, 4096
( _fd="domain.key" ; _fd_out="domain.crt" ; _len="2048" ; _days="365" ; \
openssl req -newkey rsa:${_len} -nodes \
-keyout ${_fd} -x509 -days ${_days} -out ${_fd_out} )
```

#### Generate self-signed certificate from existing private key

```bash
# _len: 2048, 4096
( _fd="domain.key" ; _fd_out="domain.crt" ; _days="365" ; \
openssl req -key ${_fd} -nodes \
-x509 -days ${_days} -out ${_fd_out} )
```

#### Generate self-signed certificate from existing private key and csr

```bash
# _len: 2048, 4096
( _fd="domain.key" ; _fd_csr="domain.csr" ; _fd_out="domain.crt" ; _days="365" ; \
openssl x509 -signkey ${_fd} -nodes \
-in ${_fd_csr} -req -days ${_days} -out ${_fd_out} )
```

#### Generate DH public parameters

```bash
( _dh_size="2048" ; \
openssl dhparam -out /etc/nginx/ssl/dhparam_${_dh_size}.pem "$_dh_size" )
```

#### Display DH public parameters

```bash
openssl pkeyparam -in dhparam.pem -text
```

#### Extract private key from pfx

```bash
( _fd_pfx="cert.pfx" ; _fd_key="key.pem" ; \
openssl pkcs12 -in ${_fd_pfx} -nocerts -nodes -out ${_fd_key} )
```

#### Extract private key and certs from pfx

```bash
( _fd_pfx="cert.pfx" ; _fd_pem="key_certs.pem" ; \
openssl pkcs12 -in ${_fd_pfx} -nodes -out ${_fd_pem} )
```

#### Extract certs from p7b

```bash
# PKCS#7 file doesn't include private keys.
( _fd_p7b="cert.p7b" ; _fd_pem="cert.pem" ; \
openssl pkcs7 -inform DER -outform PEM -in ${_fd_p7b} -print_certs > ${_fd_pem})
# or:
openssl pkcs7 -print_certs -in -in ${_fd_p7b} -out ${_fd_pem})
```

#### Convert DER to PEM

```bash
( _fd_der="cert.crt" ; _fd_pem="cert.pem" ; \
openssl x509 -in ${_fd_der} -inform der -outform pem -out ${_fd_pem} )
```

#### Convert PEM to DER

```bash
( _fd_der="cert.crt" ; _fd_pem="cert.pem" ; \
openssl x509 -in ${_fd_pem} -outform der -out ${_fd_der} )
```

#### Verification of the private key

```bash
( _fd="private.key" ; \
openssl rsa -noout -text -in ${_fd} )
```

#### Verification of the public key

```bash
# 1)
( _fd="public.key" ; \
openssl pkey -noout -text -pubin -in ${_fd} )

# 2)
( _fd="private.key" ; \
openssl rsa -inform PEM -noout -in ${_fd} &> /dev/null ; \
if [ $? = 0 ] ; then echo -en "OK\n" ; fi )
```

#### Verification of the certificate

```bash
( _fd="certificate.crt" ; # format: pem, cer, crt \
openssl x509 -noout -text -in ${_fd} )
```

#### Verification of the CSR

```bash
( _fd_csr="request.csr" ; \
openssl req -text -noout -in ${_fd_csr} )
```

#### Check the private key and the certificate are match

```bash
(openssl rsa -noout -modulus -in private.key | openssl md5 ; \
openssl x509 -noout -modulus -in certificate.crt | openssl md5) | uniq
```

#### Check the private key and the CSR are match

```bash
(openssl rsa -noout -modulus -in private.key | openssl md5 ; \
openssl req -noout -modulus -in request.csr | openssl md5) | uniq
```

___

### Tool: [secure-delete](https://wiki.archlinux.org/index.php/Securely_wipe_disk)

#### Secure delete with shred

```bash
shred -vfuz -n 10 file
shred --verbose --random-source=/dev/urandom -n 1 /dev/sda
```

#### Secure delete with scrub

```bash
scrub -p dod /dev/sda
scrub -p dod -r file
```

#### Secure delete with badblocks

```bash
badblocks -s -w -t random -v /dev/sda
badblocks -c 10240 -s -w -t random -v /dev/sda
```

### Tool: [dd](https://en.wikipedia.org/wiki/Dd_(Unix))

#### Show dd status every so often

```bash
dd <dd_params> status=progress
watch --interval 5 killall -USR1 dd
```

___

### Tool: [system-other](https://github.com/trimstray/the-book-of-secret-knowledge#tool-system-other)

#### Reboot system from init

```bash
exec /sbin/init 6
```

#### Init system from single user mode

```bash
exec /sbin/init
```

#### Show current working directory of a process

```bash
readlink -f /proc/<PID>/cwd
```

#### Show actual pathname of the executed command

```bash
readlink -f /proc/<PID>/exe
```

### Tool: [curl](https://curl.haxx.se)

```bash
curl -Iks https://www.google.com
```

* `-I` - show response headers only
* `-k` - insecure connection when using ssl
* `-s` - silent mode (not display body)

```bash
curl -Iks --location -X GET -A "x-agent" https://www.google.com
```

* `--location` - follow redirects
* `-X` - set method
* `-A` - set user-agent

```bash
curl -Iks --location -X GET -A "x-agent" --proxy http://127.0.0.1:16379 https://www.google.com
```

* `--proxy [socks5://|http://]` - set proxy server

```bash
curl -o file.pdf -C - https://example.com/Aiju2goo0Ja2.pdf
```

* `-o` - write output to file
* `-C` - resume the transfer

#### Find your external IP address (external services)

```bash
curl ipinfo.io
curl ipinfo.io/ip
curl icanhazip.com
curl ifconfig.me/ip ; echo
```

### Tool: [ssh](https://www.openssh.com/)

#### SSH connection through host in the middle

```bash
ssh -t reachable_host ssh unreachable_host
```

#### Run command over SSH on remote host

```bash
cat > cmd.txt << __EOF__
cat /etc/hosts
__EOF__

ssh host -l user $(<cmd.txt)
```

#### Get public key from private key

```bash
ssh-keygen -y -f ~/.ssh/id_rsa
```

#### Get all fingerprints

```bash
ssh-keygen -l -f .ssh/known_hosts
```

#### SSH authentication with user password

```bash
ssh -o PreferredAuthentications=password -o PubkeyAuthentication=no user@remote_host
```

#### SSH authentication with publickey

```bash
ssh -o PreferredAuthentications=publickey -o PubkeyAuthentication=yes -i id_rsa user@remote_host
```

#### Simple recording SSH session

Unser testing

#### SSH login without processing any login scripts

```bash
ssh -tt user@host bash
```

#### SSH local port forwarding

Example 1:

```bash
# Forwarding our local 2250 port to nmap.org:443 from localhost through localhost
host1> ssh -L 2250:nmap.org:443 localhost

# Connect to the service:
host1> curl -Iks --location -X GET https://localhost:2250
```

Example 2:

```bash
# Forwarding our local 9051 port to db.d.x:5432 from localhost through node.d.y
host1> ssh -nNT -L 9051:db.d.x:5432 node.d.y

# Connect to the service:
host1> psql -U db_user -d db_dev -p 9051 -h localhost
```

* `-n` - redirects stdin from `/dev/null`
* `-N` - do not execute a remote command
* `-T` - disable pseudo-terminal allocation

#### SSH remote port forwarding

```bash
# Forwarding our local 9051 port to db.d.x:5432 from host2 through node.d.y
host1> ssh -nNT -R 9051:db.d.x:5432 node.d.y

# Connect to the service:
host2> psql -U postgres -d postgres -p 8000 -h localhost
```

___

### Tool: [linux-dev](https://www.tldp.org/LDP/abs/html/devref1.html)

#### Testing remote connection to port

```bash
timeout 1 bash -c "</dev/<proto>/<host>/<port>" >/dev/null 2>&1 ; echo $?
```

* `<proto` - set protocol (tcp/udp)
* `<host>` - set remote host
* `<port>` - set destination port

#### Read and write to TCP or UDP sockets with common bash tools

```bash
exec 5<>/dev/tcp/<host>/<port>; cat <&5 & cat >&5; exec 5>&-
```

___

### Tool: [tcpdump](http://www.tcpdump.org/)

#### Filter incoming (on interface) traffic (specific <ip:port>)

```bash
tcpdump -ne -i eth0 -Q in host 192.168.252.1 and port 443
```

* `-n` - don't convert addresses (`-nn` will not resolve hostnames or ports)
* `-e` - print the link-level headers
  * `-i [iface|any]` - set interface
  * `-Q|-D [in|out|inout]` - choose send/receive direction (`-D` - for old tcpdump versions)
  * `host [ip|hostname]` - set host, also `[host not]`
  * `[and|or]` - set logic
  * `port [1-65535]` - set port number, also `[port not]`

#### Filter incoming (on interface) traffic (specific <ip:port>) and write to a file

```bash
tcpdump -ne -i eth0 -Q in host 192.168.252.1 and port 443 -c 5 -w tcpdump.pcap
```

* `-c [num]` - capture only num number of packets
* `-w [filename]` - write packets to file, `-r [filename]` - reading from file

#### Capture all ICMP packets

```bash
tcpdump -nei eth0 icmp
```

#### Check protocol used (TCP or UDP) for service

```bash
tcpdump -nei eth0 tcp port 22 -vv -X | egrep "TCP|UDP"
```

#### Display ASCII text (to parse the output using grep or other)

```bash
tcpdump -i eth0 -A -s0 port 443
```

#### Rotate capture files

```bash
tcpdump -ei eth0 -w /tmp/capture-%H.pcap -G 3600 -C 200
```

* `-G <num>` - pcap will be created every `<num>` seconds
* `-C <size>` - close the current pcap and open a new one if is larger than `<size>`

### Tool: [nmap](https://nmap.org/)

#### Ping scans the network

```bash
nmap -sP 192.168.0.0/24
```

#### Show only open ports

```bash
nmap -F --open 192.168.0.0/24
```

#### Full TCP port scan using with service version detection

```bash
nmap -p 1-65535 -sV -sS -T4 192.168.0.0/24
```

#### Nmap scan and pass output to Nikto

```bash
nmap -p80,443 192.168.0.0/24 -oG - | nikto.pl -h -
```

#### Recon specific ip:service with Nmap NSE scripts stack

```bash
# Set variables:
_hosts="192.168.250.10"
_ports="80,443"

# Set Nmap NSE scripts stack:
_nmap_nse_scripts="+dns-brute,\
                   +http-auth-finder,\
                   +http-chrono,\
                   +http-cookie-flags,\
                   +http-cors,\
                   +http-cross-domain-policy,\
                   +http-csrf,\
                   +http-dombased-xss,\
                   +http-enum,\
                   +http-errors,\
                   +http-git,\
                   +http-grep,\
                   +http-internal-ip-disclosure,\
                   +http-jsonp-detection,\
                   +http-malware-host,\
                   +http-methods,\
                   +http-passwd,\
                   +http-phpself-xss,\
                   +http-php-version,\
                   +http-robots.txt,\
                   +http-sitemap-generator,\
                   +http-shellshock,\
                   +http-stored-xss,\
                   +http-title,\
                   +http-unsafe-output-escaping,\
                   +http-useragent-tester,\
                   +http-vhosts,\
                   +http-waf-detect,\
                   +http-waf-fingerprint,\
                   +http-xssed,\
                   +traceroute-geolocation.nse,\
                   +ssl-enum-ciphers,\
                   +whois-domain,\
                   +whois-ip"

# Set Nmap NSE script params:
_nmap_nse_scripts_args="dns-brute.domain=${_hosts},http-cross-domain-policy.domain-lookup=true,"
_nmap_nse_scripts_args+="http-waf-detect.aggro,http-waf-detect.detectBodyChanges,"
_nmap_nse_scripts_args+="http-waf-fingerprint.intensive=1"

# Perform scan:
nmap --script="$_nmap_nse_scripts" --script-args="$_nmap_nse_scripts_args" -p "$_ports" "$_hosts"
```

___

### Tool: [netcat](http://netcat.sourceforge.net/)

```bash
nc -kl 5000
```

* `-l` - listen for an incoming connection
* `-k` - listening after client has disconnected
* `>filename.out` - save receive data to file (optional)

```bash
nc 192.168.0.1 5051 < filename.in
```

* `< filename.in` - send data to remote host

```bash
nc -vz 10.240.30.3 5000
```

* `-v` - verbose output
* `-z` - scan for listening daemons

```bash
nc -vzu 10.240.30.3 1-65535
```

* `-u` - scan only udp ports

#### Transfer data file (archive)

```bash
server> nc -l 5000 | tar xzvfp -
client> tar czvfp - /path/to/dir | nc 10.240.30.3 5000
```

#### Launch remote shell

```bash
# 1)
server> nc -l 5000 -e /bin/bash
client> nc 10.240.30.3 5000

# 2)
server> rm -f /tmp/f; mkfifo /tmp/f
server> cat /tmp/f | /bin/bash -i 2>&1 | nc -l 127.0.0.1 5000 > /tmp/f
client> nc 10.240.30.3 5000
```

#### Create a single-use TCP or UDP proxy

```bash
### TCP -> TCP
nc -l -p 2000 -c "nc [ip|hostname] 3000"

### TCP -> UDP
nc -l -p 2000 -c "nc -u [ip|hostname] 3000"

### UDP -> UDP
nc -l -u -p 2000 -c "nc -u [ip|hostname] 3000"

### UDP -> TCP
nc -l -u -p 2000 -c "nc [ip|hostname] 3000"
```

### Tool: [netstat](https://en.wikipedia.org/wiki/Netstat)

#### Monitor open connections for specific port including listen, count and sort it per IP

```bash
watch "netstat -plan | grep :443 | awk {'print \$5'} | cut -d: -f 1 | sort | uniq -c | sort -nk 1"
```

___

### Tool: [rsync](https://en.wikipedia.org/wiki/Rsync)

#### Rsync remote data as root using sudo

```bash
rsync --rsync-path 'sudo rsync' username@hostname:/path/to/dir/ /local/
```

### Tool: [awk](http://www.grymoire.com/Unix/Awk.html)

#### Search for matching lines

```bash
# egrep foo
awk '/foo/' filename
```

#### Search non matching lines

```bash
# egrep -v foo
awk '!/foo/' filename
```

#### Print matching lines with numbers

```bash
# egrep -n foo
awk '/foo/{print FNR,$0}' filename
```

#### Print the last column

```bash
awk '{print $NF}' filename
```

#### Find all the lines longer than 80 characters

```bash
awk 'length($0)>80{print FNR,$0}' filename
```

#### Print only lines of less than 80 characters

```bash
awk 'length < 80' filename
```

#### Print double new lines a file

```bash
awk '1; { print "" }' filename
```

#### Print line numbers

```bash
awk '{ print FNR "\t" $0 }' filename
awk '{ printf("%5d : %s\n", NR, $0) }' filename   # in a fancy manner
```

#### Print line numbers for only non-blank lines

```bash
awk 'NF { $0=++a " :" $0 }; { print }' filename
```

#### Print the line and the next two (i=5) lines after the line matching regexp

```bash
awk '/foo/{i=5+1;}{if(i){i--; print;}}' filename
```

#### Print the lines starting at the line matching 'server {' until the line matching '}'

```bash
awk '/server {/,/}/' filename
```

#### Print multiple columns with separators

```bash
awk -F' ' '{print "ip:\t" $2 "\n port:\t" $3' filename
```

#### Remove empty lines

```bash
awk 'NF > 0' filename
```

#### Delete trailing white space (spaces, tabs)

```bash
awk '{sub(/[ \t]*$/, "");print}' filename
```

#### Delete leading white space

```bash
awk '{sub(/^[ \t]+/, ""); print}' filename
```

#### Remove duplicate consecutive lines

```bash
# uniq
awk 'a !~ $0{print}; {a=$0}' filename
```

#### Remove duplicate entries in a file without sorting

```bash
awk '!x[$0]++' filename
```

#### Exclude multiple columns

```bash
awk '{$1=$3=""}1' filename
```

#### Substitute foo for bar on lines matching regexp

```bash
awk '/regexp/{gsub(/foo/, "bar")};{print}' filename
```

#### Add some characters at the beginning of matching lines

```bash
awk '/regexp/{sub(/^/, "++++"); print;next;}{print}' filename
```

### Tool: [sed](http://www.grymoire.com/Unix/Sed.html)

#### Print a specific line from a file

```bash
sed -n 10p /path/to/file
```

#### Remove a specific line from a file

```bash
sed -i 10d /path/to/file

#### Remove a range of lines from a file

```bash
sed -i <file> -re '<start>,<end>d'
```

#### Replace newline(s) with a space

```bash
sed ':a;N;$!ba;s/\n/ /g' /path/to/file
```

* `:a` create a label `a`
* `N` append the next line to the pattern space
* `$!` if not the last line, ba branch (go to) label `a`
* `s` substitute, `/\n/` regex for new line, `/ /` by a space, `/g` global match (as many times as it can)

### Tool: [grep](http://www.grymoire.com/Unix/Grep.html)

#### Search for a "pattern" inside all files in the current directory

```bash
grep -rn "pattern"
grep -RnisI "pattern" *
fgrep "pattern" * -R
```

```bash
grep -e -- filename
grep -- -- filename
grep "\-\-" filename
```

#### Remove blank lines from a file and save output to new file

```bash
grep . filename > newfilename
```
