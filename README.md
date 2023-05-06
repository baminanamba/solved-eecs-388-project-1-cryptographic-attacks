Download Link: https://assignmentchef.com/product/solved-eecs-388-project-1-cryptographic-attacks
<br>



Intro to Computer Security

<h1>Project 1: Cryptographic Attacks</h1>

This is a group project; you will work in teams of two and submit one project per team. Please find a partner as soon as possible. If have trouble forming a team, post to Piazza’s partner search forum. The final exam will cover project material, so you and your partner should collaborate on each part.

The code and other answers your group submits must be entirely your own work, and you are bound by the Honor Code. You may consult with other students about the conceptualization of the project and the meaning of the questions, but you may not look at any part of someone else’s solution or collaborate with anyone outside your group. You may consult published references, provided that you appropriately cite them (e.g., with program comments), as you would in an academic paper.

<h1>Introduction</h1>

In this project, you will investigate vulnerabilities in widely used cryptographic hash functions, including length-extension attacks and collision vulnerabilities, and an implementation vulnerability in a popular digital signature scheme. In Part 1, we will guide you through attacking the authentication capability of an imaginary server API. The attack will exploit the length-extension vulnerability of hash functions in the MD5 and SHA family. In Part 2, you will use a cutting-edge tool to generate different messages with the same MD5 hash value (collisions). You’ll then investigate how that capability can be exploited to conceal malicious behavior in software. In Part 3, you will learn about an attack against certain implementations of RSA padding; then, you will forge a digital signature using your own implementation of this attack.

Objectives:

<ul>

 <li>Understand how to apply basic cryptographic integrity and authentication primitives.</li>

 <li>Investigate how cryptographic failures can compromise the security of applications.</li>

 <li>Appreciate why you should use HMAC-SHA256 as a substitute for common hash functions.</li>

 <li>Understand why padding schemes are integral to cryptographic security.</li>

</ul>

<h1>Part 1. Length Extension</h1>

In most applications, you should use MACs such as HMAC-SHA256 instead of plain cryptographic hash functions (e.g. MD5, SHA-1, or SHA-256), because hashes, also known as digests, fail to match our intuitive security expectations. What we really want is something that behaves like a pseudorandom function, which HMACs seem to approximate and hash functions do not.

One difference between hash functions and pseudorandom functions is that many hashes are subject to <em>length extension</em>. All the hash functions we’ve discussed use a design called the Merkle-Damgård construction. Each is built around a <em>compression function f </em>and maintains an internal state <em>s</em>, which is initialized to a fixed constant. Messages are processed in fixed-sized blocks by applying the compression function to the current state and current block to compute an updated internal state, i.e. <em>s<sub>i</sub></em><sub>+1 </sub>= <em>f</em>(<em>s<sub>i</sub></em><em>,b<sub>i</sub></em>). The result of the final application of the compression function becomes the output of the hash function.

A consequence of this design is that if we know the hash of an <em>n</em>-block message, we can find the hash of longer messages by applying the compression function for each block <em>b<sub>n</sub></em><sub>+1</sub><em>,b<sub>n</sub></em><sub>+2</sub><em>,… </em>that we want to add. This process is called length extension, and it can be used to attack many applications

of hash functions.

<h2>1.1         Experiment with Length Extension in Python</h2>

To experiment with this idea, we’ll use a Python implementation of the MD5 hash function, though SHA-1 and SHA-256 are vulnerable to length extension too. You can download the pymd5 module at <a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/pymd5.py">https://www.eecs.umich.edu/courses/eecs388/static/project1/pymd5.py</a> <sub>and learn</sub>

how to use it by running $ pydoc pymd5. To follow along with these examples, run Python in interactive mode ($ python -i) and run the command from pymd5 import md5, padding.

Consider the string “Use HMAC, not hashes”. We can compute its MD5 hash by running:

m = “Use HMAC, not hashes” h = md5()

h.update(m) print h.hexdigest() or, more compactly, print md5(m).hexdigest(). The output should be:

3ecc68efa1871751ea9b0b1a5b25004d

MD5 processes messages in 512-bit blocks, so, internally, the hash function pads <em>m </em>to a multiple of that length. The padding consists of the bit 1, followed by as many 0 bits as necessary, followed by a 64-bit count of the number of bits in the unpadded message. (If the 1 and count won’t fit in the current block, an additional block is added.) You can use the function padding(<em>count</em>) in the pymd5 module to compute the padding that will be added to a <em>count </em>-bit message.

Even if we didn’t know m, we could compute the hash of longer messages of the general form m + padding(len(m)*8) + <em>suffix </em>by setting the initial internal state of our MD5 function to

MD5(m), instead of the default initialization value, and setting the function’s message length counter to the size of <em>m </em>plus the padding (a multiple of the block size). To find the padded message length, guess the length of <em>m </em>and run bits = (<em>length_of_m </em>+ len(padding(<em>length_of_m</em>*8)))*8.

The pymd5 module lets you specify these parameters as additional arguments to the md5 object: h = md5(state=”3ecc68efa1871751ea9b0b1a5b25004d”.decode(“hex”), count=512)

Now you can use length extension to find the hash of a longer string that appends the suffix “Good advice.” Simply run:

x = “Good advice” h.update(x) print h.hexdigest()

to execute the compression function over x and output the resulting hash. Verify that it equals the MD5 hash of m + padding(len(m)*8) + x. Notice that, due to the length-extension property of MD5, we didn’t need to know the value of m to compute the hash of the longer string—all we needed to know was m’s length and its MD5 hash.

This component is intended to introduce length extension and familiarize you with the Python MD5 module we will be using; you will not need to submit anything for it.

<h2>1.2        Conduct a Length Extension Attack</h2>

Length extension attacks can cause serious vulnerabilities when people mistakenly try to construct something like an HMAC by using <em>hash</em>(<em>secret </em>k <em>message</em>)<a href="#_ftn1" name="_ftnref1"><sup>[1]</sup></a>. The National Bank of EECS 388, which is not up-to-date on its security practices, hosts an API that allows its client-side applications to perform actions on behalf of a user by loading URLs of the form:

<a href="https://eecs388.org/project1/api?token=402a574d265dc212ee64970f159575d0&amp;user=admin&amp;command1=ListFiles&amp;command2=NoOp">https://eecs388.org/project1/api?token=402a574d265dc212ee64970f159575d0</a>

<a href="https://eecs388.org/project1/api?token=402a574d265dc212ee64970f159575d0&amp;user=admin&amp;command1=ListFiles&amp;command2=NoOp">&amp;user=admin&amp;command1=ListFiles&amp;command2=NoOp</a>

where token is MD5(<em>user’s 8-character password </em>k user= …[<em>the rest of the URL starting from user= and ending with the last command</em>]).

Using the techniques that you learned in the previous section and without guessing the password, apply length extension to create a URL ending with &amp;command3=UnlockAllSafes that is treated as valid by the server API. You have permission to use our server to check whether your command is accepted.

<em>Hint: </em>You might want to use the quote() function from Python’s urllib module to encode non-ASCII characters in the URL.

<em>Historical fact: </em>In 2009, security researchers found that the API used by the photo-sharing site Flickr suffered from a length-extension vulnerability almost exactly like the one in this exercise.

What to submit         A Python 2.x script named len_ext_attack.py that:

<ol>

 <li>Accepts a valid URL in the same form as the one above as a command line argument.</li>

 <li>Modifies the URL so that it will execute the UnlockAllSafes command as the user.</li>

 <li>Successfully performs the command on the server and prints the server’s response.</li>

</ol>

You should make the following assumptions:

<ul>

 <li>The input URL will have the same form as the sample above, but we may change the server hostname and the values of token, user, command1, and command2 (although they will remain in the same order). These values may be of substantially different lengths than in the sample.</li>

 <li>The input URL may be for a user with a different password, but the length of the password will be unchanged.</li>

 <li>The server’s output might not exactly match what you see during testing.</li>

</ul>

You can base your code on the following example:

import httplib, urlparse, sys url = sys.argv[1]

# Your code to modify url goes here

parsedUrl = urlparse.urlparse(url)

conn = httplib.HTTPSConnection(parsedUrl.hostname,parsedUrl.port) conn.request(“GET”, parsedUrl.path + “?” + parsedUrl.query) print conn.getresponse().read()

<h1>Part 2. MD5 Collisions</h1>

MD5 was once the most widely used cryptographic hash function, but today it is considered dangerously insecure. This is because cryptanalysts have discovered efficient algorithms for finding <em>collisions</em>—pairs of messages with the same MD5 hash value.

The first known collisions were announced on August 17, 2004, by Xiaoyun Wang, Dengguo Feng, Xuejia Lai, and Hongbo Yu. Here’s one pair of colliding messages they published:

Message 1:

d131dd02c5e6eec4693d9a0698aff95c 2fcab58712467eab4004583eb8fb7f89 55ad340609f4b30283e488832571415a 085125e8f7cdc99fd91dbdf280373c5b d8823e3156348f5bae6dacd436c919c6 dd53e2b487da03fd02396306d248cda0 e99f33420f577ee8ce54b67080a80d1e c69821bcb6a8839396f9652b6ff72a70 Message 2:

d131dd02c5e6eec4693d9a0698aff95c 2fcab50712467eab4004583eb8fb7f89 55ad340609f4b30283e4888325f1415a 085125e8f7cdc99fd91dbd7280373c5b d8823e3156348f5bae6dacd436c919c6 dd53e23487da03fd02396306d248cda0 e99f33420f577ee8ce54b67080280d1e c69821bcb6a8839396f965ab6ff72a70

Convert each group of hex strings into a binary file.

(On Linux, run $ xxd -r -p file.hex &gt; file.)

<ol>

 <li>What are the MD5 hashes of the two binary files? Verify that they’re the same.</li>

</ol>

($ openssl dgst -md5 file1 file2<sub>)</sub>

<ol start="2">

 <li>What are their SHA-256 hashes? Verify that they’re different.</li>

</ol>

($ openssl dgst -sha256 file1 file2<sub>)</sub>

This component is intended to introduce you to MD5 collisions; you will not submit anything for it.

<h2>2.1        Generating Collisions Yourself</h2>

In 2004, Wang’s method took more than 5 hours to find a collision on a desktop PC. Since then, researchers have introduced vastly more efficient collision finding algorithms. You can compute your own MD5 collisions using a tool written by Marc Stevens that uses a more advanced technique. You can download the fastcoll tool here: <a href="http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip">http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5.exe.zip</a> (Windows executable) or <a href="http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip">http://www.win.tue.nl/hashclash/fastcoll_v1.0.0.5-1_source.zip</a> (source code)

If you are building fastcoll from source, you can compile using this makefile: <a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/Makefile">https://www. </a><a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/Makefile">eecs.umich.edu/courses/eecs388/static/project1/Makefile</a><a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/Makefile">.</a> You will also need the

Boost libraries. On Ubuntu, you can install these using apt-get install libboost-all-dev. On OS X, you can install Boost via the <a href="https://brew.sh/">Homebrew package manager</a> using brew install boost.

<ol>

 <li>Generate your own collision with this tool. How long did it take?</li>

</ol>

($ time fastcoll -o file1 file2<sub>)</sub>

<ol start="2">

 <li>What are your files? To get a hex dump, run $ xxd -p file.</li>

 <li>What are their MD5 hashes? Verify that they’re the same.</li>

 <li>What are their SHA-256 hashes? Verify that they’re different.</li>

</ol>

What to submit                       A text file named generating_collisions.txt containing your answers.

Format your file using this template. Make sure to follow the format precisely as this part is autograded:

# Question 1

<em>time_for_fastcoll </em>(e.g. 3.456s)

# Question 2 file1: <em>file1_hex_dump </em>file2: <em>file2_hex_dump </em># Question 3 <em>md5_hash</em>

# Question 4 file1: <em>file1_sha256_hash </em>file2:

<em>file2_sha256_hash</em>

<h2>2.2        A Hash Collision Attack</h2>

The collision attack lets us generate two messages with the same MD5 hash and any chosen

(identical) prefix. Due to MD5’s length-extension behavior, we can append any suffix to both messages and know that the longer messages will also collide. This lets us construct files that differ only in a binary “blob” in the middle and have the same MD5 hash, i.e. <em>prefix </em>k <em>blob<sub>A </sub></em>k <em>suffix </em>and <em>prefix </em>k <em>blob<sub>B </sub></em>k <em>suffix</em>.

We can leverage this to create two programs that have identical MD5 hashes but wildly different behaviors. We’ll use Python, but almost any language would do. Put the following three lines into a file called prefix:

#!/usr/bin/python

# -*- coding: utf-8 -*blob = “””

and put these three lines into a file called suffix:

“””

from hashlib import sha256 print sha256(blob).hexdigest()

Now use fastcoll to generate two files with the same MD5 hash that both begin with prefix.

($ fastcoll -p prefix -o col1 col2). Then append the suffix to both ($ cat col1 suffix &gt; file1.py; cat col2 suffix &gt; file2.py). Verify that file1.py and file2.py have the

same MD5 hash but generate different output.

Extend this technique to produce another pair of programs, good and evil, that also share the same MD5 hash. One program should execute a benign payload: print “I come in peace.” The second should execute a pretend malicious payload: print “Prepare to be destroyed!”. Note that we may rename these program before grading them.

What to submit          Two Python 2.x scripts named good.py and evil.py that have the same MD5 hash, have different SHA-256 hashes, and print the specified messages.

<h1>Part 3. RSA Signature Forgery</h1>

A secure implementation of RSA encryption or digital signatures requires a proper padding scheme. RSA without padding, also known as <em>textbook RSA</em>, has several undesirable properties. One property is that it is trivial for an attacker with only an RSA public key pair (<em>n</em><em>,e</em>) to produce a mathematically valid (message<em>,</em>signature) pair by choosing an <em>s </em>and returning (<em>s<sup>e</sup></em><em>,s</em>).

In order to prevent an attacker from being able to forge valid signatures in this way, RSA implementations use a padding scheme to provide structure to the values that are encrypted or signed. The most commonly used padding scheme in practice is defined by the PKCS #1 v1.5 standard, which can be found at <a href="https://tools.ietf.org/html/rfc2313">https://tools.ietf.org/html/rfc2313</a><a href="https://tools.ietf.org/html/rfc2313">.</a> The standard defines, among other things, the format of RSA keys and signatures and the procedures for generating and validating RSA signatures.

<h2>3.1         Validating RSA Signatures</h2>

You can experiment with validating RSA signatures yourself. Create a text file called key.pub that contains the following RSA public key:

—–BEGIN PUBLIC KEY—–

MFowDQYJKoZIhvcNAQEBBQADSQAwRgJBALvMZ+YhjwKpteNYzzbPHvPqdvMrs2Rf HeIhK+ui9v0YHNyFW6aBwwG/6sfbvxx4OlePBWjRhpoxDC5A/J+rVXkCAQM=

—–END PUBLIC KEY—–

Confirm that the key has a 512-bit modulus with an exponent of 3. You can view the modulus and public exponent of this key by running:

$ openssl rsa -in key.pub -pubin -text -noout

Create a file containing only the text EECS 388 rul3z! ($ echo -n ’EECS 388 rul3z!’ &gt;

myfile). The following is a base64-encoded signature of the file using the private key corresponding to the public key above.

kbenR8AWBIKUroVOqfUFJKL61+8EFu88yKPRg+o/XGCWLFlxTaVWyDnDE2UciNns NcFQRaNev5+nCxMCUfZbZw==

Copy the base64-encoded signature to a file, and then convert it from base64 to raw binary. ($ base64 –decode -i sig.b64 &gt; sig). Verify the signature against the file you created:

$ openssl dgst -sha1 -verify key.pub -signature sig myfile

We can also use basic math operations in Python to explore this signature further. Remember, RSA ciphertexts, plaintexts, exponents, moduli, and signatures are actually all integers.

Usually, you would use a cryptography library to import a public key. However, for the purposes of this part of the assignment, you can just manually assign the modulus and exponent as integers in Python based on the earlier output from OpenSSL. You may find the following command useful: $ openssl rsa -in key.pub -text -noout -pubin | egrep ‘^ ‘ | tr -d ‘ :
’

Launch Python in interactive mode and assign the modulus and the exponent to integer variables:

# n is the modulus from the key.

# You can just assign it as a hexadecimal literal–remember to start with 0x # It will look something like:

n = 0x00d56d87ba372303f8<sub>…</sub>104dd059e49e435f

# e is the exponent from the key e = 3

We can also load the signature into Python. Like the modulus and the exponent, we’ll convert the signature to an integer:

signature = int(open(‘sig’).read().encode(‘hex’), 16)

Now reverse the signing operation by computing signature<sup>e </sup>mod n: x = pow(signature, e, n)

You can print the resulting value as a 64-byte (512-bit) integer in hex: print “%0128x” % x

You should see something like 0001fffff…f82b4557c1d37f99c6d6f5ff00900.

Verify that the last 20 bytes of this value match the SHA-1 hash of your file:

import hashlib m = hashlib.sha1()

m.update(“EECS 388 rul3z!”) print m.hexdigest()

The hash has been padded using the PKCS #1 v1.5 signature scheme, which specifies that, for a SHA-1 hash with a <em>k</em>-bit RSA key, the signed value will contain the following bytes: 0001F<u>FFFF</u>F ··· FF003<u>021300906052B</u>0E<u>03021A0500041</u>4X<u>XXXXX</u>XX ··· <u>X</u>X

| {z} | {z } | {z } <em>k</em><em>/</em>8−38 bytes ASN.1 “magic” bytes denoting type of hash algorithm SHA-1 digest (20 bytes)

The number of FF bytes varies such that the size of the result is equal to the size of the RSA key. Confirm that the value you computed above matches this format. It is crucial for implementations to verify that <em>every bit </em>is exactly as it should be, but sometimes developers can be lazy…

<h2>3.2       Bleichenbacher’s Attack</h2>

It’s tempting for an implementer to validate the signature padding as follows: (1) confirm that the total length equals the key size; (2) strip off the bytes 0001, followed by <em>any number </em>of FF bytes, then 00; (3) parse the ASN.1 bytes; (4) verify that the next 20 bytes are the correct SHA-1 digest.

This procedure does not check the length of the FF bytes, nor does it verify that the hash is in the least significant (rightmost) bytes of the string. As a result, it will accept malformed values that have “garbage” bytes following the digest, like this example, which has only one FF:

0001<strong>FF</strong>003<u>021300906052B</u>0E<u>03021A0500041</u>4 X<u>XXXX</u>X ··· XX <strong>YYYYYYYY </strong>··· <strong><sub>YY</sub></strong>

|                                {z                                 } |           {z           } |             {z                }

ASN.1 “magic” bytes denoting type of hash algorithm        SHA-1 digest (20 bytes) <em>k</em><em>/</em>8−39 arbitrary bytes

Convince yourself that this value would be accepted by the incorrect implementation described above, and that the bytes at the end labeled YY would be ignored. When an implementation uses this lenient, incorrect parsing, an attacker can easily create forged signatures that it will accept.

This possibility is particularly troubling when RSA is used with <em>e </em>= 3. Consider the case with RSA encryption: If we encrypt an unpadded message <em>m </em>that is much shorter than <em>k</em>-bits, then <em>m</em><sup>3 </sup><em>&lt; n</em>. Thus, the “encrypted” message <em>c </em>= <em>m<sup>e </sup></em>= <em>m</em><sup>3 </sup>mod <em>n </em>does not “wrap around” the modulus <em>n</em>. In this case, RSA doesn’t provide good security, since the attacker can simply take the normal cube root of the ciphertext to find the plaintext, <em>m </em>= <em>c</em><sup>1</sup><em><sup>/</sup></em><sup>3</sup>. It’s easy to reverse normal exponentiation, as opposed to modular exponentiation!

Now recall that RSA signature validation is analogous to RSA encryption. If the signature uses <em>e </em>= 3, the validator calculates <em>s<sup>e </sup></em>= <em>s</em><sup>3 </sup>mod <em>n </em>and checks that the result is the correct PKCS-padded digest of the signed message.

Here comes the attack: For a 2048-bit key, a correctly padded value for an RSA signature using a SHA-1 hash should have <em>k</em><em>/</em>8−38 = 2048<em>/</em>8−38 = 218 bytes of FFs. But what if there were only one FF, as in the example shown above? This would leave space for 217 arbitrary bytes at the end of the value. A correct implementation of signature validation would notice the extra bytes and reject the signature, but the weak implementation described above would ignore these bytes.

To construct a signature that would validate against such an implementation, the attacker needs to find a number <em>x </em>such that <em>x</em><sup>3 </sup><em>&lt; n </em>and where <em>x</em><sup>3 </sup>matches the format of the malformed example shown above. Since the implementation ignores the last 217 bytes, the attacker has enough flexibility to find a perfect cube of this form. To do this, you can construct an integer whose most significant bytes have the correct format, including the digest of the target message, and set the last 217 bytes to 00. Then take the cube root, rounding as appropriate.

<em>Historical fact: </em>This attack was discovered by Daniel Bleichenbacher, who presented it in a lightning talk at the rump session at the Crypto 2006 conference. His talk is described in this mailing list post: <a href="https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE">https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE</a><a href="https://mailarchive.ietf.org/arch/msg/openpgp/5rnE9ZRN1AokBVj3VqblGlP63QE"><sub>.</sub></a><sub> At</sub>

the time, many important implementations of RSA signatures were found to be vulnerable to this attack, including OpenSSL. In 2014, the Firefox TLS implementation was also found to be vulnerable to this type of attack: <a href="https://www.mozilla.org/security/advisories/mfsa2014-73/">https://www.mozilla.org/security/advisories/mfsa2014-73/</a><a href="https://www.mozilla.org/security/advisories/mfsa2014-73/">.</a>

<h2>3.3        Constructing Forged Signatures</h2>

The National Bank of EECS 388 has a website at <a href="https://eecs388.org/project1/">https://eecs388.org/project1/</a> that its employees use to initiate wire transfers between bank accounts. To authenticate each transfer request, the control panel requires a signature from a particular 2048-bit RSA key that is listed on the website’s home page. Unfortunately, this control panel is running old, unpatched software that is vulnerable to signature forgery.

Using the signature forgery technique described above, produce an RSA signature that the National Bank of EECS 388 site accepts as valid.

What to submit         A Python script called bleichenbacher.py that:

<ol>

 <li>Accepts a double-quoted string as a command-line argument.</li>

 <li>Prints a base64-encoded forged signature of the input string.</li>

</ol>

You have our permission to use <a href="https://eecs388.org/project1/">https://eecs388.org/project1/</a> to test your signatures, but when we grade your program it will not have access to the network.

We have provided a Python library, roots.py, that provides several useful functions that you may wish to use when implementing your solution. You can download roots.py at <a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/roots.py">https://www.eecs. </a><a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/roots.py">umich.edu/courses/eecs388/static/project1/roots.py</a><a href="https://www.eecs.umich.edu/courses/eecs388/static/project1/roots.py">.</a> To examine its documentation, run $ pydoc roots.

To use these functions, you will have to import roots.py. You can start with the following template: from roots import * import hashlib import sys message = sys.argv[1]

# Your code to forge a signature goes here. print integer_to_base64(forged_signature)

<h1>Part 4. Writeup</h1>

<ol>

 <li>With reference to the construction of HMAC, explain how changing the design of the API in Part 1.2 to use token= HMAC<em><sub>user’s password</sub></em>(user=…) would avoid the length extension vulnerability.</li>

 <li>Briefly explain why the technique you explored in Part 2.2 poses a danger to systems that rely on digital signatures to verify the integrity of programs before they are installed or executed. Examples include Microsoft Authenticode and most Linux package managers. (You may assume that these systems sign MD5 hashes of the programs.)</li>

 <li>Since 2010, NIST has specified that RSA public exponents (<em>e</em>) should be at least 2<sup>16 </sup>+ Briefly explain why Bleichenbacher’s attack would not work for these keys.</li>

</ol>

What to submit        A text file named writeup.txt containing your answers.

<h1>Submission Checklist</h1>

Upload to Canvas a gzipped tarball (.tar.gz) named project1.<em>uniqname1</em>.<em>uniqname2</em>.tar.gz that contains only the files listed below. These will be autograded, so make sure you have the proper filenames and behaviors. You can generate the tarball at the shell using this command:

tar -zcf project1.<em><sub>uniqname1</sub></em>.<em><sub>uniqname2</sub></em>.tar.gz len_ext_attack.py  generating_collisions.txt good.py evil.py bleichenbacher.py writeup.txt

<h2>Part 1.2</h2>

len_ext_attack.py: A Python script that accepts a URL as a command-line argument, performs the specified attack, and outputs the server’s response.

Part 2.2 generating_collisions.txt: A text file with your answers to the four short questions, using the provided template.

<h2>Part 2.3</h2>

good.py and evil.py: Two Python scripts that share an MD5 hash, have different SHA-256 hashes, and print the specified messages.

<h2>Part 3.3</h2>

bleichenbacher.py: A Python script that accepts a string as a command-line argument and outputs a forged signature for that string that is considered valid by the bank website.

<h2>Part 4</h2>

writeup.txt: A text file containing your answers to the three writeup questions.

<a href="#_ftnref1" name="_ftn1">[1]</a> k is the symbol for contatenation, i.e. “hello” k “world” = “helloworld”.