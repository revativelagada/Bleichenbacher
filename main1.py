
import rsa1
import random
import time

from collections import namedtuple

Interval = namedtuple('Interval', ['lower_bound', 'upper_bound'])


modulus_size = int(input("enter modulus size:"))
pk, sk = rsa1.generate_key(modulus_size)
(n, e) = pk

# modulus size in bytes
k = modulus_size // 8

# global start timer
t_start = time.perf_counter()

# keep track of the oracle calls
global queries
queries = 0

# math.ceil and math.floor don't work for large integers
ceil = lambda a, b: a // b + (a % b > 0)
floor = lambda a, b: a // b


def PKCS1_encode(message, total_bytes):
    """
    length(PKCS1(M)) = total_bytes(key size in bytes)
    """
    # 11 = 3 constant bytes(00,02,00) and at aleast 8 bytes for padding
    if len(message) > total_bytes - 11:
        raise Exception("Message is too big for encoding.")
    
    pad_len = total_bytes - 3 - len(message)

    # non-zero padding bytes
    padding = bytes(random.sample(range(1, 256), pad_len))

    encoded = b'\x00\x02' + padding + b'\x00' + message

    return encoded


def PKCS1_decode(encoded):
    #first two bytes are removed--only index 2 to end are considered
    encoded = encoded[2:]
    #index corresponding to zeroth byte(after padding) is taken
    idx = encoded.index(b'\x00')
    #next to 0th byte is our msg 
    message = encoded[idx + 1:]

    return message


def oracle(ciphertext):
    
    global queries

    queries += 1
    t = time.perf_counter()
    if queries % 500 == 0:
        print("Query #{} ({} s)".format(queries, round(t - t_start, 3)))

    encoded = rsa1.decrypt_string(sk, ciphertext)

    if len(encoded) > k:
        raise Exception("Invalid PKCS1 encoding after decryption.")
    
    if len(encoded) < k:
        zero_pad = b'\x00' * (k - len(encoded)) #b'\x00\x00--exp times
        encoded = zero_pad + encoded
    
    return encoded[0:2] == b'\x00\x02'


def prepare(message):
    
    message_encoded = PKCS1_encode(message, k)
    
    ciphertext = rsa1.encrypt_string(pk, message_encoded)

    return ciphertext


# Step 2.A.(starting the search)
def find_smallest_s(lower_bound, c):
    """
    Find the smallest s >= lower_bound, s>=n/3B
    """
    s = lower_bound

    while True:
        attempt = (c * pow(s, e, n)) % n
        attempt = rsa1.integer_to_bytes(attempt)

        if oracle(attempt):
            return s

        s += 1


# Step 2.C.
def find_s_in_range(a, b, prev_s, B, c):
    """ 
    if one interval is present----
    reduce the search only to relevant regions (determined by r)
    """
    ri = ceil(2 * (b * prev_s - 2 * B), n)

    while True:
        si_lower = ceil(2 * B + ri * n, b)
        si_upper = ceil(3 * B + ri * n, a)

        for si in range(si_lower, si_upper):
            attempt = (c * pow(si, e, n)) % n
            attempt = rsa1.integer_to_bytes(attempt)

            if oracle(attempt):
                return si
        
        ri += 1


def safe_interval_insert(M_new, interval):

    for i, (a, b) in enumerate(M_new):
        
        # overlap found, construct the larger interval
        if (b >= interval.lower_bound) and (a <= interval.upper_bound):
            lb = min(a, interval.lower_bound)
            ub = max(b, interval.upper_bound)

            M_new[i] = Interval(lb, ub)
            return M_new
    
    # no overlaps found, just insert the new interval
    M_new.append(interval)

    return M_new


# Step 3.
def update_intervals(M, s, B):
    

    M_new = []

    for a, b in M:
        r_lower = ceil(a * s - 3 * B + 1,  n)
        r_upper = ceil(b * s - 2 * B,  n)

        for r in range(r_lower, r_upper):
            lower_bound = max(a, ceil(2 * B + r * n,  s))
            upper_bound = min(b, floor(3 * B - 1 + r * n, s))

            interval = Interval(lower_bound, upper_bound)

            M_new = safe_interval_insert(M_new, interval)

    M.clear()

    return M_new


def bleichenbacher(ciphertext):
    

    # Step 1. is only needed when the ciphertext is
    # not PKCS1 conforming

    # integer value of ciphertext
   
    c = rsa1.bytes_to_integer(ciphertext)
   
   
    B = 2 ** (8 * (k - 2))

    M = [Interval(2 * B, 3 * B - 1)]
    ''' 
    flag = 1
    if not(oracle(ciphertext)):
        s0 = random.randint(a,b) #limits(a,b) teliyav
        attempt = (c * pow(s0, e, n)) % n
        attempt = utils.integer_to_bytes(attempt)
        if not(oracle(attempt)):
            s0 += 1
        else:
            flag = 0
            c = utils.bytes_to_integer(attempt)
    '''      
    # Step 2.A.
    s = find_smallest_s(ceil(n, 3 * B), c)

    M = update_intervals(M, s, B)

    while True:
        # Step 2.B. if more than one interval is present
        if len(M) >= 2:
            s = find_smallest_s(s + 1, c)

        # Step 2.C.
        elif len(M) == 1:
            a, b = M[0]

            # Step 4.
            if a == b:
                
                    return rsa1.integer_to_bytes(a % n) #blinding is not done
            '''
                else:
                    return utils.integer_to_bytes((a*(utils.modinv(s0,n)))% n)
            '''
            s = find_s_in_range(a, b, s, B, c)
            
        M = update_intervals(M, s, B)


def main():
    
        message = (input("Enter Message: "))
        message = bytes(message, 'utf-8')
       
        ciphertext = prepare(message)
       
    #   print("The ciphertext in bytes")
       
       #print(ciphertext)
       # print("".join(chr(x) for x in bytearray(ciphertext)))# string la print cheydaniki
        
       # ciphertext = (input("enter ciphertext:")) 
        #ciphertext= bytes(ciphertext, 'utf-8') # bytes maripotunnai.ila ivodhu, direct ga vellani
        
        
        decrypted = bleichenbacher(ciphertext)
        decrypted = PKCS1_decode(decrypted)

        assert decrypted == message

        print("queries:\t{}".format(queries))
       #print("message:\t{}".format(message))
        print("decrypt:\t{}".format(decrypted))

        

if __name__ == '__main__':
    main()
   
