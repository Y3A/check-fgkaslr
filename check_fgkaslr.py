#!/usr/bin/python3
import sys
import argparse

parser = argparse.ArgumentParser(description='Checks for symbols not affected by fgkaslr.\nYou need two different dumps of /proc/kallsyms for this to work.', formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('file1', help='file containing first dump', type=str)
parser.add_argument('file2', help='file containing second dump', type=str)
args = parser.parse_args()

def file_len(fname):
    with open(fname, 'r') as f:
        for i, l in enumerate(f):
            pass
    return i + 1

if file_len(args.file1) != file_len(args.file2):
    print("Error, the two files do not contain the same amount of symbols!")
    sys.exit(1)

f1 = open(args.file1, 'r')
f2 = open(args.file2, 'r')
lines1 = f1.readlines()
lines2 = f2.readlines()
f1.close()
f2.close()

def compute(lines):
    ret = {}
    docomp = False
    for line in lines:
        line = line.strip()
        if "T startup_64" in line:
            base = int('0x' + line.split()[0], 16)
            docomp = True
        if docomp:
            delta = int('0x' + line.split()[0], 16) - base
            ret.update({line.split()[2]: delta})
    return ret

def compare(dic1, dic2):
    final = {}
    for i in dic1:
        if dic1[i] == dic2[i]:
            final.update({i: dic1[i]})
    return final

syms1 = compute(lines1)
syms2 = compute(lines2)
nochange = compare(syms1, syms2)

f = open('no_fgkaslr.txt', 'w')
for i in nochange:
    f.write(hex(nochange[i]) + ' ' +  i + '\n')
f.close()

print('Complete! Result stored in no_fgkaslr.txt as {offset} {symbol name}')
