#!/usr/bin/env python3
import os.path
import subprocess
import sys
import shlex

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


def check_args():
    # Check for correct number of arguments
    if len(sys.argv) != 2:
        print("Error: Incorrect syntax.")
        print(f"Usage: python {os.path.basename(sys.argv[0])} <input_file_path>")
        sys.exit(1)

    # Check if provided file is a valid IPA file
    ipa_file = sys.argv[1]
    ipa_file_check = subprocess.getoutput("file " + ipa_file)
    if "Zip" not in ipa_file_check:
        print("\033[91m {}\033[00m".format("Incorrect file format. Please provide a valid IPA file for analysis."))
        sys.exit(1)
    return ipa_file


def path_retrieval(ipa_file):
    # Retrieve Mach-O binary file path
    ipa_file_name = ipa_file.split('.')[0]
    zip_file = ipa_file_name + '.zip'
    subprocess.run(['cp', ipa_file, zip_file], check=True)
    subprocess.run(['unzip', zip_file], check=True)
    ipa_folder = 'Payload'
    app_bundle = subprocess.getoutput('ls ' + ipa_folder)
    app_bundle_name = app_bundle.split('.')[0]
    file_path = f'{ipa_folder}/{app_bundle}/{app_bundle_name}'
    app_binary_path = os.path.realpath(file_path)
    return app_binary_path


def filecheck(app_binary_path):
    # Check if provided file can be analyzed
    file_check = subprocess.check_output(['file', app_binary_path], text=True)
    if "Mach-O" in file_check:
        print("\033[95m {}\033[00m".format("\nAnalyzing our target iOS application binary.\n"))
    else:
        print("\033[91m {}\033[00m".format("Provided app binary is not suitable for analysis."))
        sys.exit()


def check1(app_binary_path):
    # Check 1: Does the iOS app binary have ASLR (Address Space Layout Randomization) enabled?
    aslr_check = subprocess.getoutput("otool -hv " + shlex.quote(app_binary_path) + " | grep PIE")
    if "PIE" in aslr_check:
        print('[+] ASLR enabled:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
    else:
        print('[+] ASLR enabled:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check2(app_binary_path):
    # Check 2: Does the iOS app binary have stack smashing protection enabled?
    canary_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep stack_chk")
    if "stack_chk_guard" and "stack_chk_fail" in canary_check:
        print('[+] Stack canaries enabled:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
    else:
        print('[+] Stack canaries enabled:', "\033[91m {}\033[00m".format('No'), sep=' ')

def check3(app_binary_path):
    # Check 3: Does the iOS app binary have ARC (Automatic Reference Counting) enabled?
    arc_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep objc_release")
    if "objc_release" in arc_check:
        print('[+] ARC enabled:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
    else:
        print('[+] ARC enabled:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check4(app_binary_path):
    # Check 4: Is the iOS app binary encrypted?
    crypt_check = subprocess.getoutput("otool -arch all -Vl " + shlex.quote(app_binary_path) + " | grep -A5 LC_ENCRYPT")
    if "cryptid 1" in crypt_check:
        print('[+] Binary Encrypted:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
    else:
        print('[+] Binary Encrypted:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check5(app_binary_path):
    # Check 5: Does the iOS app binary have weak hashing algorithms enabled?
    MD5_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_CC_MD5'")
    SHA1_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_CC_SHA1'")
    if "_CC_MD5" in MD5_check or "_CC_SHA1" in SHA1_check:
        print('[+] Weak Hashing Algorithms present:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
        hashes = {MD5_check: 'MD5', SHA1_check: 'SHA1'}
        alg = []
        for check in hashes:
            if check:
                alg.append(hashes[check])
        print('   [-] Algorithms: ', "\033[92m {}\033[00m".format(', '.join(hashes)))

    else:
        print('[+] Weak Hashing Algorithms present:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check6(app_binary_path):
    # Check 6: Does the iOS app binary use insecure random number generator?
    random_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_random'")
    srand_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_srand'")
    rand_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_rand'")
    if "_random" in random_func_check or "_srand" in srand_func_check or "_rand" in rand_func_check:
        print('[+] Insecure Random Number Generator functions present:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
        rand_gen = {random_func_check: '_random', srand_func_check: '_srand', rand_func_check: '_rand'}
        insec_rand = []
        for check in rand_gen:
            if check:
                insec_rand.append(rand_gen[check])
        print('   [-] Functions: ', "\033[92m {}\033[00m".format(', '.join(insec_rand)))
    else:
        print('[+] Insecure Random Number Generator functions present:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check7(app_binary_path):
    # Check 7: Does the iOS app binary use insecure malloc function?
    malloc_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_malloc'")
    if "_malloc" in malloc_check:
        print('[+] Insecure Malloc Function present:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
    else:
        print('[+] Insecure Malloc Function present:', "\033[91m {}\033[00m".format('No'), sep=' ')


def check8(app_binary_path):
    # Check 8: Does the iOS app binary use deprecated APIs?
    gets_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_gets'")
    memcpy_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_memcpy'")
    strncpy_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_strncpy'", )
    strlen_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_strlen'")
    vsnprintf_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_vsnprintf'")
    sscanf_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_sscanf'")
    strtok_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_strtok'")
    alloca_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_alloca'")
    sprintf_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_sprintf'")
    printf_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_printf'")
    vsprintf_func_check = subprocess.getoutput("otool -Iv " + shlex.quote(app_binary_path) + " | grep -w '_vsprintf'")
    if "_gets" in gets_func_check or "_memcpy" in memcpy_func_check or "_strncpy" in strncpy_func_check or "_strlen" in strlen_func_check or "_vsnprintf" in vsnprintf_func_check or "_sscanf" in sscanf_func_check or "_strtok" in strtok_func_check or "_alloca" in alloca_func_check or "_sprintf" in sprintf_func_check or "_printf" in printf_func_check or "_vsprintf" in vsprintf_func_check:
        print('[+] Insecure and Vulnerable Functions present:', "\033[92m {}\033[00m".format('Yes'), sep=' ')
        funcs = {gets_func_check: '_gets', memcpy_func_check: '_memcpy', strncpy_func_check: '_strncpy',
                 strlen_func_check: '_strlen', vsnprintf_func_check: '_vsnprintf', sscanf_func_check: '_sscanf',
                 strtok_func_check: '_strtok', alloca_func_check: '_alloca', sprintf_func_check: '_sprintf',
                 printf_func_check: '_printf', vsprintf_func_check: '_vsprintf'}
        vuln_funcs = []
        for check in funcs:
            if check:
                vuln_funcs.append(funcs[check])
        print('   [-] Functions: ', "\033[92m {}\033[00m".format(', '.join(vuln_funcs)))
    else:
        print('[+] Insecure and Vulnerable Functions present:', "\033[91m {}\033[00m".format('No'), sep=' ')


def main():
    ipa = check_args()
    binary_path = path_retrieval(ipa)
    filecheck(binary_path)
    check1(binary_path)
    check2(binary_path)
    check3(binary_path)
    check4(binary_path)
    check5(binary_path)
    check6(binary_path)
    check7(binary_path)
    check8(binary_path)


if __name__ == main():
    main()
