from ctypes import CDLL
from ctypes.util import find_library

libc = CDLL(find_library("c"))

shuffled = "amnrttrafgldtgsoigndnsstiie tirne oaai-onlnviHuN vicsa  rntl,ttrylu u hnmE np thi r ne ei maaitp  ast  iWs_nn oarei_ca -e s ser s thdmsEwaetotsitreeiprunTat wui t shenfe fgatieletW ehnsd gAiadebea dpoafce aior ae iedi   eannr hherttrd hiadmey hsln_ anea.rm ca, ahe eus cs.shtl  eoyehonpgxe.,aeap}e ns ogesoptOpgstoec x sip_sxyemnteepl sintdnarlc_te, osspetetwpitan c;hore ,a?r_n ehvieti,raygpcyld  o ntnomet  t  te lope t tle ncdyheuheesees tieeyroelntta eoe{aul yceddusa oseotcto lr  faemvdeansl go torhaoastnafn.saosa nhn ceac ah s ,r x ernalrHgugye hihnc ed t tselte  di eexidsnushneg asiyinatcslmadf d eceeo2nmu salernitprs teormeeht  rhghle lesihvueeoeta lefesumhacm sdtd  yg er ersvettans  l_oo  sathdwtpyei2erlso ehadbirm"
shuffled = [x for x in shuffled]
message = shuffled 
seed = libc.time(0)

def shuffle(msg):
    for i in range(len(msg)-1, -1, -1):
            v3 = libc.rand() % (i + 1);
            print(v3)
            temp = msg[i];
            msg[i] = msg[v3];
            msg[v3] = temp;

def unshuffle(enc):
    rands_list = []

    for _ in range(22):
        temp = []
        for i in range(len(message)-1, -1, -1):
            temp.append(libc.rand()%(i+1))
        rands_list.append(temp)

    rands_list = rands_list[::-1]

    for j in range(22):
        rands = rands_list[j][::-1]
        for i, l in enumerate(enc):
            enc[i], enc[rands[i]] = enc[rands[i]], l

while "lactf" not in ''.join(shuffled).lower():
    # seed = 0x67a71bd5
    shuffled = "amnrttrafgldtgsoigndnsstiie tirne oaai-onlnviHuN vicsa  rntl,ttrylu u hnmE np thi r ne ei maaitp  ast  iWs_nn oarei_ca -e s ser s thdmsEwaetotsitreeiprunTat wui t shenfe fgatieletW ehnsd gAiadebea dpoafce aior ae iedi   eannr hherttrd hiadmey hsln_ anea.rm ca, ahe eus cs.shtl  eoyehonpgxe.,aeap}e ns ogesoptOpgstoec x sip_sxyemnteepl sintdnarlc_te, osspetetwpitan c;hore ,a?r_n ehvieti,raygpcyld  o ntnomet  t  te lope t tle ncdyheuheesees tieeyroelntta eoe{aul yceddusa oseotcto lr  faemvdeansl go torhaoastnafn.saosa nhn ceac ah s ,r x ernalrHgugye hihnc ed t tselte  di eexidsnushneg asiyinatcslmadf d eceeo2nmu salernitprs teormeeht  rhghle lesihvueeoeta lefesumhacm sdtd  yg er ersvettans  l_oo  sathdwtpyei2erlso ehadbirm"
    libc.srand(seed)
    shuffled = [x for x in shuffled]
    unshuffle(shuffled)
    print(seed)
    seed -= 1

print(''.join(shuffled))