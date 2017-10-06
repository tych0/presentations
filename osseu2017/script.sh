#!/bin/bash

# mount propagation
echo -e "#!/bin/sh\necho evil!\n" >> evil.sh
chmod +x evil.sh
unshare -m --propagation unchanged
mount --bind evil.sh /bin/ls

docker run --rm -it --privileged --cap-add all --security-opt seccomp=unconfined --security-opt apparmor=unconfined --device-cgroup-rule "c *:* rwm" --device-cgroup-rule "b *:* rwm" ubuntu

mknod mymem c 1 1

mkdir mydev
mount -t devpts mydev mydev
