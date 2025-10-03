# This line is the most likely source of your error.
# It tells the build system to compile hello.c into hello.o
# and then link it into the final hello.ko module.
obj-m += kac_netctl.o

USER_PROG = interact/interact_with_netctl

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules
	gcc -static -o ${USER_PROG} interact/interact.c


clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
	rm -f ${USER_PROG}