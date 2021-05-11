# check-fgkaslr

Python script to identify the symbols that are not affected by fgkaslr <br/>
Useful during kernel pwn ctfs

+ cat /proc/kallsyms and save the result to a text file
+ reboot the emulated kernel and repeat the step above
+ clean the output such that the two files start and end with contents of /proc/kallsyms
+ run script and view output in no_fgkaslr.txt
