---
layout: post
title: RPISEC NUKE
---


## Overview:

![Main Menu]({{ site.baseurl }}/images/menu.png)

RPISEC Nuke is a wargame, the premise being that you are a rogue hacker out to create chaos and launch other countries nukes. There are three keys which we need to crack, pwn and or otherwise subvert in order to gain access to the nukes. The first key is a simple comparison check, your standard password challenge. The second key appears to be an AES-128 based challenge in which you enter a key and some plaintext. The third key is a more complicated challenge based around xoring with a seeded rand. It should be noted that we only get 3 attempts total before we are locked out of the program, and that we're on a 5 minute timer. Another obstacle to note is that there are a lot of animations in this wargame. In order to efficently test them, I patched my local copy of the binary to simply return on _usleep which made it almost instant to test exploits rather than waiting up to 3 minutes between trials.

![Programming Nukes]({{ site.baseurl }}/images/programMenu.png)

Once all three keys have been correctly entered(or worked around), a new option opens up and you gain the ability to program the warhead. A hex string must be entered and an algorthm bypassed in order to finally launch your nukes!

## Key Auth One

![Key 1]({{ site.baseurl }}/images/key1.png)

I took an initial look in IDA and in relatively short time found the relevant strncmp function. I loaded up the nuke program in gdb and set a breakpoint at that address. Multiple runs showed that the key is static, "D3E60C90579EEE92EFD46898A911B0AF". Entering this allows us to bypass the first key with relatively little fuss.

![Crucial Key1]({{ site.baseurl }}/images/key1strncmp.png)

## Key Auth Two

![Key 2]({{ site.baseurl }}/images/key2.png)

Key 2 is much more involved than key 1, from the difficulty of reversing to the exploit itself. Initial reversing was challenging as structs are used throughout which are very tricky to track. To make sense of all these bits I used IDA's struct function, going through the function and labeling all instances the struct used through their implied context.

![Structs]({{ site.baseurl }}/images/decodedStructs.png)

 After I decoded all the structs, It was a little easier to read through the disassembly. I found out that they use openssl's implementation of AES so unlikely that it's a pure RE challenge. Despite this, I determined that they do 2 separate rounds of AES encryption, once with your plaintext and your key using a static IV, and once with their plaintext and their key. The ultimate goal being to have the two match as the string "KING CROWELL" I started looking at key 3 as key 1 was too simple to contain any real vuln. I found this free in key 3 which actually frees the same memory as used in key 2 leaving dangling pointers to 2's structure in 3.

![Challenge]({{ site.baseurl }}/images/challenge.png)

This vulnerability allows us to fail 2's challenge but initialize the structure which is then exposed through the 64 byte challenge printing in key 3. More reversing found that the exact structure ends up as 32 bytes of plaintext, 16 bytes of the IV for AES and 16 bytes of the true key. The only problem is that before the key is shown in key3 it is xor'd with rand integer by integer. So it looks like it's time to break rand. They do give us the time somewhat delayed but in main, rand is seeded with the current time and a seemingly random heap address.

![IV]({{ site.baseurl }}/images/key2IV.png)

My first thought was to try to simply brute force rand using a library such as untwister, checking my work with the known IV values, but after some more RE I found that they actually print out this address as the "launch session id" in the main menu. This simplifies our task substantially as all we need to do now is input the time we're provided added with the leaked address. Unfortunately the server was running 2 hours behind local time and there's a few seconds of gaps between when they seed rand and when they print it, so my initial attempts were unsuccessful.

![rand]({{ site.baseurl }}/images/key3rand.png)

I ended up taking the local time as soon as I connected and again when I was provided with time in order to calculate the difference and get the true time rand was seeded with. This actually worked, providing me with the true seed of random.

![Final Requirements]({{ site.baseurl }}/images/key2kingcrowell.png)

Armed with this knowledge I xored the last 16 bytes of the challenge key with the correct values of rand() and got their true key. From there I simply had to provide their plaintext (KING CROWELL) along with the known IV's and completed key 2.


## Key Auth Three

![key3 initial]({{ site.baseurl }}/images/key3_failed.png)

Key auth 3 was interesting in that it was so closely interweaven with key 2, as they both allocate the same structures over each other due to the free bug in key 3. Initially I tried to reverse this key without looking at key auth 2 knowing that I controlled random, but I found that there was an easier way. If we again look at where the key structures in 2 and 3 line up, we find that the last 16 bits of our key 2 ciphertext actually line up perfectly with the "winkey" of key 3!

Knowing this, we needed to find a plaintext which would make the last 16 bits of our ciphertext equal to "31337". I used the following snippet of code to take the known IV values along with an arbitrary key that I supplied and pass them to AES to decrypt my desired key.

```
# Encryption
IV = struct.pack("I", 0xFEEDFACF)
IV = IV + (struct.pack("I", 0xDEADC0DE))
IV = IV + (struct.pack("I", 0xBABECAFE))
IV = IV + (struct.pack("I", 0x0A55B00B))
eleet = struct.pack("I", 0x031337) + "A" * 12
king_krule = "KING CROWELL" + "\x00" * 4
endCipher = king_krule + eleet
aes_key = '\x00'*16

eprint("IV: " + IV)
eprint("cipher Text: " + eleet)
encryption_suite = AES.new(aes_key, AES.MODE_CBC, IV)
plain_text = encryption_suite.decrypt(endCipher)
```

Because AES is symmetric, upon encryption by rpisec\_nuke, my desired plaintext will be the cipher text! Most of the difficulty of this key was the reversing, once I understood all the inputs to AES and how the structs lined up it was relatively simply to create this code and bypass key3. 


## NUKE86.OS Programming

So on to the exciting part, launching nukes! We've managed to scheme our way past all three keys and now we should just be able to hit the massive red "Nuke the Planet" button right? Not exactly. Once you enter all three keys you still have a little bit more work to do. When accessing the nuke programming option(4), you are greeted with a screen that asks for a hex string representing a launch checksum. Entering an incorrect checksum will abort the launch and throw away your hard earned keys. 

![Checksum]({{ site.baseurl }}/images/checksum.png)

Some reversing lets us stop blindly entering hex and actually get a sense of what they're asking. In order to pass the checksum the final result after their algorithm is applied must be equal to all three of the general's key xored together: 0xdcdc59a9. In order to achieve this result you have to work with a rolling xor, they take each int of your string and xor it together along with the string END. In order to input whatever data we need and still arrive at a result of the general's combined xored keys, I created the following function.

```
# Payload must be a multiple of 4
# checksum is desired checksum output, end is simply an additional xored string.
def generateCheckSum(payload, checksum, end):
    payloadArrays = [payload[i:i+4] for i in range(0, len(payload), 4)]
    payloadXor = 0
    for dword in payloadArrays:
        dword = struct.unpack("I", dword)[0]
        payloadXor ^= dword
    return (payload + struct.pack("I", payloadXor ^ checksum ^ end)).encode("hex")
```

![launchOption]({{ site.baseurl }}/images/launchOption.png)

This lets me enter any data I want (% 4) and will output the correct string that passes the checksum. Once we past the checksum we are greeted with what appears to be a simulated operating system. Essentially this "operating system" is a switch statement which reads in data from the string used for the checksum character by character. This switch has a number of options, typing "DOOM" will cause a nuke to be launched and "DISARM" will cancel the launch. Typing "\x53" will write the next char in the input buffer to a targetting buffer. Typing "0x49" increments the pointer to that targeting buffer. Typing "0x52" will allow you to enter a new checksum and "reprogram the nuke". Finally, typing END will also shutdown the nuke.

![gotime]({{ site.baseurl }}/images/nukelaunch.png)

The first thing to do obviously was to launch a random nuke by typing DOOM. After that I started looking at exactly what I needed to do in order to control the nuke's target. I found that if I used \x53 in combination with \x49, then I could both write and increment the targeting buffer allowing me to do this:


![byeClark]({{ site.baseurl }}/images/general_clark.png)

RIP General Clark.

With that out of the way I decided to look for ways to escape this switch statement and get the final password to finish the game. From reversing the structure, I knew that the targeting buffer started at \x208 within the structure and at \x288 and \x28C there were function pointers to disarm and detonate nuke respectively. So I needed to increment \x80 and 140 times respectively in order to leak a known functions address(using "\x4F") and then overwrite the detonate function. Leaking the address allowed me to calculate relative offsets to important functions like system (Not that that would have been too helpful ;). 

I was able to cause a segfault using the above technique and reliably leak an address but unfortunately ran out of time and was unable to complete the rop in order to gain a shell through execve. Detonate in particular was a useful function to overwrite as it is already called using a user controlled buffer as an argument. In my testing to create a rop chain I know I would have needed to stack pivot as my current location was not very useful and would have dropped me into arbitrary memory after my one return.

Finally, in an expression of how upset I was about being unable to finish the rop in this timeframe (Planning on working on it over the summer) I decided that I wanted to watch the world burn.

```
import subprocess
procs = []
for i in xrange(1337):
    procs.append(subprocess.Popen(["python2","/home/nihliphobe/School/mbe/MBE/src/project2/report/exploit/nukes.py"]))
for p in procs:
    p.wait()
```

![watchtheworldburn]({{ site.baseurl }}/images/watchtheworldburn.png)


### Exploit Automation

My code is fully contained in a single function and requires no input from the user, see the gists below:

  -Main: https://gist.github.com/3a5e261ec0ea5dfce87fab6d88719bb0

  -Launch Nuke on General Clark: https://gist.github.com/1a6abe807335e92b0022116114c626ca

  -Assorted notes: https://gist.github.com/0098a21feb8a6f379c3ae5fa24ea5aec

Usage: python2 main.py
