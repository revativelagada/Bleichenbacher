Theory Behind: 
When there is a secure RSA key exchange between a server and a client and the padding used is PKCS #1 V1.5, it is prone to Bleichenbacher attack.

PKCS #1 Encoding:
In this format, the message is encoded in such a way that the first two bytes are 00 and 02 followed by a padding string of non zero bytes. The next byte is 00. After this, the original message is present. The length of the non zero padding bytes should be at least eight bytes. The length of this PKCS encoded message is equal to the byte length of public key n. The length of the message should not exceed k-11 where k is length of public key n in bytes, 11 bytes are for three constant bytes (00,02,00) and at least eight bytes for padding string. 

Description of the attack:
The client encrypts a PKCS encoded message with the public exponent (e)  c=m^e mod n and sends c to the server.  The server decrypts the received message with the private exponent (d) c^d mod n and says whether the decrypted message is PKCS conforming. If it is not PKCS conforming, the server sends a message stating that it is bad data. 
Any message m that is PKCS conforming satisfies 2B<= m<3B i.e m belongs to [2B, 3B).

B= 2^8*(k-2) where k is key size in bytes.

An attacker who has access to the server chooses a ciphertext c,multiplies it with a random integer 's' c x s^e mod n and sends it to the server. The server decrypts it. If the decrypted message is PKCS conforming, the following holds.
2B<= ms mod n <=3B-1 
There exists an integer r such that 2B <= ms-rn<= 3B-1
2B+rn<=ms<=3B-1+rn
(2B+rn)/m<=s<=(3B-1+rn)/m 

Based on the response of the server, the attacker keeps on sending several messages to the server with different values of s in the given range until the attacker gets information about the original message m. For each successful s, the attacker finds the interval in which the message lies. When there is only one interval and is of size 1, the attacker multiplies it with s^-1 mod n and finds the original message m.

Step by Step Explanation:
1. Blinding
The attacker chooses a ciphertext c, multiplies it with a random integer s0 such that 
c0 = c* s0^e mod n is PKCS conforming which is known by accessing the server. This is not an important step and is done only if the ciphertext is not PKCS conforming.
If it is PKCS conforming, then the message belongs to the interval M={[2B, 3B-1]}.
2. Search for PKCS conforming messages
2a: Start the search for s
Choose the smallest integer s (s>= n/3B) in such a way that c0* s^e mod n is PKCS conforming.  
2B <= ms-rn<= 3B-1     Also, 2B<=m<=3B-1 
rn<=(3B-1)*s-2B
r<=((3B-1)*s-2B)/n
r<(3B*s)/n
If r<1 then s=n/3B 
Hence, initiate s with this value.
2b: If M>=2
If the message belongs to more than one interval, then choose the smallest s greater than the s in the previous iteration such that the resulting message is PKCS conforming.
i.e  choose s(i)>s(i-1) such that c0*(s(i)^e) mod n is PKCS conforming.

2c:
If the message belongs to only one interval M = {[a,b]} and a is not equal to b, then choose small 
r(i) and s(i) such that
 r(i)>= 2 * ((b *s(i-1)) - 2B)/n
(2B+r(i)n)/b <= s(i) < (3B+r(i)n)/a 
Repeat this until c0*(s(i)^e) mod n is PKCS conforming.

3. Deal with interval overlaps when a new interval is added to the list.
Once s(i) has been chosen, the interval M = {[a,b]} is updated as follows.
New intervalM = {[max(a, (2B+rn)/s(i)), min(b,(3B-1+rn)/s(i))]} and (a* s(i)-3B+1)/n<=r<=(b* s(i)-2B)/n

4. Compute the answer m
If there is just one interval M = {[a,b]} and a equals b, then a = m* s0. The attacker finds the multiplicative inverse of s0, multiplies it with a mod n and gets the original message m.

