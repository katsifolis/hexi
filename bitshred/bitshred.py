import os, sys, re, glob 
from bloomfilter import BloomFilter
from pprint import pprint as pp

NGRAM=10 * 2 # 5 n-gram size - 2 multiplier because byte in hex is represented by 2 digits
BLOOM_SIZE = 10000 # Bloom filter size
HASH_COUNT = 3 # Hash-counter

# gets a sequence from bytes
# b byte buffer
# n: size a of a shred in bytes
def shredder(b, n):
    lst = []
    p = 0 # pointer to beginning of slice
    tmp = b[p:n:1]
    while len(tmp) >= 1:
        lst.append(tmp)
        p += n
        tmp = b[p:n+p:1]

    return lst

# Fill the bloom filter
def blossom(shreds):
    bloom = BloomFilter(BLOOM_SIZE, HASH_COUNT)
    for vv in shreds:
        bloom.add(vv)

    return bloom

# Calculates the jaccard index between two files A, B
def calc_jaccard(A, B):
    and_score = 0
    or_score = 0
    for a, b in zip(A, B):
        and_score += a & b # F11
        or_score  += a | b # F01 + F10 + F11

    jaccard = and_score / or_score
    return jaccard

# Reads the information jj
def get_execution_seg(folder):
    shreds = {}
    for file in glob.glob("test/dumps/*"):
        f = open(file, "rb")
        x_seg = os.popen("readelf -SW " + str(file) + " | grep AX", "r") 
        b = BloomFilter(100,10)
        segment = {} # dictionary containing offsets mapped to size
        for v in x_seg:
            output = re.sub(" +", " ", v).split(" ")
            name = output[2]   # name of segment
            offset = output[5] # offset from the start of the file
            segment[offset] = output[6]

        exec_str = ""
        for off, size in segment.items():
            f.seek(int(off, 16))
            chunk = f.read(int(size, 16))
            exec_str += chunk.hex()


        shred = shredder(exec_str, NGRAM)
        shreds[os.path.basename(f.name)] = shred

    return shreds


shreds = get_execution_seg("../test/dumps/target")
blo_dict = {}
for i, v in shreds.items():
    blo_dict[i] = blossom(v)

for name, v in blo_dict.items():
    jaccard = calc_jaccard(v, blo_dict["target"])
    print("The similarity index between target and " + name + " is " + "{:.1%}".format(jaccard))
