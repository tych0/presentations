# in linuxkit dir

make
./bin/moby build linuxkit.yml
./bin/linuxkit run linuxkit

nsenter -t 1 -m
touch /bin/foo

poweroff
