from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))

def unshuffle(message, seed):
    # Convert string to list once
    chars = list(message)
    libc.srand(seed)
    
    # Pre-calculate all random numbers
    n = len(chars)
    rands = []
    print(f"\nRandom numbers for seed {seed}:")
    for round_num in range(22):
        temp = []
        print(f"\nRound {round_num + 1}:")
        for i in range(n - 1, -1, -1):
            rand_val = libc.rand() % (i + 1)
            temp.append(rand_val)
            print(f"{rand_val}", end=" ")
        rands.append(temp)
    print("\n")
    
    # Apply unshuffling
    for rand_seq in rands[::-1]:
        for i, rand_val in enumerate(rand_seq[::-1]):
            chars[i], chars[rand_val] = chars[rand_val], chars[i]
    
    return ''.join(chars)

def find_flag():
    message = "soolliWssiptre. e2se.h eparthngnutrer uosmegm_yah  elf,non rerltnhi;eneddah cv idonfiur u eo.l  e mnaf ee rtgar heeomamccl hoehcor. ihew_h oacyomeht_leysnh ryheeEamsciabcnex ce tOa  gyeu suteosnt h- tosssa tnaede d  ipxhsmpoep,m rneiadiWdnetcdpn iisefiro es e}eer o ear,nyrhee at laestt o ts seesoatfhsan  sopeeoe EdsetepdydrlaaHtaa alocligetl gldeaer tAvc ?i sntaat  decessea  dtnent tihci fhsrso ser aehaeedssoguuTpct edlnslraielu rntp dhdra mt s aeltl  e_ner aa,n,eude pant -nnsnv in gwptiiyeetda ahespt ,cyxestssrnutthioceuit,{t itna a tw lemggetnnHsyfshss_ssv l  thpaui  eoc2eg tetlggnaasym  vn   ia _etivaotnsetd rtpirr   ly ytoaeedihreltee iswetntorginN  si  atgenar se  dbi tflrnoncaadimlm nanuhho  rxaeoo_ meae pihttxie"
    seed = libc.time(0)
    
    while True:
        result = unshuffle(message, seed)
        if "lactf" in result.lower():
            return result, seed
        seed -= 1

result, final_seed = find_flag()
print(f"Found with seed: {final_seed}")
print(f"Result: {result}")