#!/bin/bash

# mount propagation
echo -e "#!/bin/sh\necho evil!\n" >> evil.sh
chmod +x evil.sh
unshare -m --propagation unchanged
mount --bind evil.sh /bin/ls

docker run --rm -it --privileged --cap-add all --security-opt seccomp=unconfined --security-opt apparmor=unconfined --device-cgroup-rule "c *:* rwm" --device-cgroup-rule "b *:* rwm" ubuntu


mkdir -p /bad
mount -t ext4 /dev/vda1 /bad
# drop block devices rule

head -c20 /dev/kmem
# add apparmor rules about /dev/kmem

mkdir -p /bad
mount --bind /dev /bad
# add bind mount rules

mknod c 1 1 /tmp/mymem
head -c20 /tmp/mymem
# drop character devices rules
# drop --privileged
