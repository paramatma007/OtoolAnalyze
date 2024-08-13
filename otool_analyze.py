#!/usr/bin/env python3
import os.path
import subprocess
import sys

print("\033[96m {}\033[00m".format(""""                                                                                                                                            
  ,ad8888ba,                                      88            db                                  88                                      
 d8"'    `"8b     ,d                              88           d88b                                 88                                      
d8'        `8b    88                              88          d8'`8b                                88                                      
88          88  MM88MMM  ,adPPYba,    ,adPPYba,   88         d8'  `8b      8b,dPPYba,   ,adPPYYba,  88  8b       d8  888888888   ,adPPYba,  
88          88    88    a8"     "8a  a8"     "8a  88        d8YaaaaY8b     88P'   `"8a  ""     `Y8  88  `8b     d8'       a8P"  a8P_____88  
Y8,        ,8P    88    8b       d8  8b       d8  88       d8""""""""8b    88       88  ,adPPPPP88  88   `8b   d8'     ,d8P'    8PP"""""""  
 Y8a.    .a8P     88,   "8a,   ,a8"  "8a,   ,a8"  88      d8'        `8b   88       88  88,    ,88  88    `8b,d8'    ,d8"       "8b,   ,aa  
  `"Y8888Y"'      "Y888  `"YbbdP"'    `"YbbdP"'   88     d8'          `8b  88       88  `"8bbdP"Y8  88      Y88'     888888888   `"Ybbd8"'  
                                                                                                            d8'                             
                                                                                                           d8'                              """))


# Enter the file path of the target iOS app Binary.
file_path = str(input("Enter the file path of your target iOS app binary: "))
app_binary_path = os.path.realpath(file_path)

#Check if provided file can be analyzed
file_check = subprocess.getoutput("file " + app_binary_path)
if "Mach-O" in file_check:
    print("\033[95m {}\033[00m".format("Analyzing our target iOS application binary."))
else:
    print("\033[91m {}\033[00m".format("Provided app binary is not suitable for analysis."))
    sys.exit()

#Check 1: Does the iOS app binary have ASLR (Address Space Layout Randomization) enabled?
PIE_check = subprocess.getoutput("otool -hv " + app_binary_path + " | grep PIE")
if "PIE" in PIE_check:
    print('[+] PIE enabled:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] PIE enabled:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 2: Does the iOS app binary have stack smashing protection enabled?
canary_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep stack_chk")
if "stack_chk_guard" and "stack_chk_fail" in canary_check:
    print('[+] Stack canaries enabled:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Stack canaries enabled:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 3: Does the iOS app binary have ARC (Automatic Reference Counting) enabled?
arc_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep objc_release")
if "objc_release" in arc_check:
    print('[+] ARC enabled:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] ARC enabled:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 4: Is the iOS app binary encrypted?
crypt_check = subprocess.getoutput("otool -arch all -Vl " + app_binary_path + " | grep -A5 LC_ENCRYPT")
if "cryptid 1" in crypt_check:
    print('[+] Binary Encrypted:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Binary Encrypted:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 5: Does the iOS app binary have weak hashing algorithms enabled?
MD5_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_CC_MD5'")
SHA1_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_CC_SHA1'")
if "_CC_MD5" in MD5_check or "_CC_SHA1" in SHA1_check:
    print('[+] Weak Hashing Algorithms present:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Weak Hashing Algorithms present:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 6: Does the iOS app binary use insecure random number generator?
random_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_random'")
srand_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_srand'")
rand_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_rand'")
if "_random" in random_func_check or "_srand" in srand_func_check or "_rand" in rand_func_check:
    print('[+] Insecure Random functions present:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Insecure Random functions present:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 7: Does the iOS app binary use insecure malloc function?
malloc_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_malloc'")
if "_malloc" in malloc_check:
    print('[+] Insecure Malloc Function present:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Insecure Malloc Function present:', "\033[91m {}\033[00m" .format('No'), sep=' ')

#Check 8: Does the iOS app binary use deprecated APIs?
gets_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_gets'")
memcpy_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_memcpy'")
strncpy_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_strncpy'",)
strlen_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_strlen'")
vsnprintf_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_vsnprintf'")
sscanf_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_sscanf'")
strtok_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_strtok'")
alloca_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_alloca'")
sprintf_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_sprintf'")
printf_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_printf'")
vsprintf_func_check = subprocess.getoutput("otool -Iv " + app_binary_path + " | grep -w '_vsprintf'")
if "_gets" in gets_func_check or "_memcpy" in memcpy_func_check or "_strncpy" in strncpy_func_check or "_strlen" in strlen_func_check or "_vsnprintf" in vsnprintf_func_check or "_sscanf" in sscanf_func_check or "_strtok" in strtok_func_check or "_alloca" in alloca_func_check or "_sprintf" in sprintf_func_check or "_printf" in printf_func_check or "_vsprintf" in vsprintf_func_check:
    print('[+] Insecure and Vulnerable Functions present:', "\033[92m {}\033[00m" .format('Yes'), sep=' ')
else:
    print('[+] Insecure and Vulnerable Functions present:', "\033[91m {}\033[00m" .format('No'), sep=' ')



