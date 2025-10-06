#! /usr/bin/env python3

key1 = 'BKSEC{rev3r5e_r@t'
key2 = '})12387642t234g789_UaD_t3h_@Uhc}eheh_n0ul_1Uv_Al_'

reverse_key2 = key2[::-1]

flag = key1 + reverse_key2

print(flag)