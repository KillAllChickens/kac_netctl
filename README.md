# kac_netctl

A kernel module designed for use within KACOS.  
Allows a user space application to block all netwrok traffic at the kernel level.
`interact/` has an example script to toggle networking  

to build, run `make` in the projects root.  
to install, run `sudo insmod kac_netctl.ko` after `make`.  

to enable(testing), use `./interact/interact_with_netctl on`  
to disable(testing), use `./interact/interact_with_netctl off`  
to check(testing), use `./interact/interact_with_netctl status`  

