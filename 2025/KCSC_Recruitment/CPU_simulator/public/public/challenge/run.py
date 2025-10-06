#!/usr/bin/env python3
import os

n = int(input("number of instruction: "))
print("input instrution")
a = []
for i in range(n):
    data = input()
    a.append(data)

file_name = "/home/ctf/input.txt"
with open(file_name, "w") as file:
    for i in a:
        file.write(i + "\n")

os.system("/home/ctf/emulator")
