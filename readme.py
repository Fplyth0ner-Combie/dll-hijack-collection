#!/usr/bin/python
"""
This is the project readme file automatic generator.
"""

from signify.authenticode import SignedPEFile
from signify.authenticode import AuthenticodeVerificationResult
import os
import re

def get_signature_status(file_path):
    signer = "N/A"
    verify = "×"
    
    with open(file_path, "rb") as file_obj:
        try:
            pe = SignedPEFile(file_obj)
            for signed_data in pe.signed_datas:
                if signer != "N/A":
                    break
                for cert in signed_data.certificates:
                    cn = re.findall(r'CN=(.+?), O=', str(cert.subject.dn))[0].replace("\\", "")
                    if "Code Signing" in cn:
                        continue
                    signer = cn
                    break


            result, e = pe.explain_verify()
            if result == AuthenticodeVerificationResult.OK:
                verify = "√"

        except:
            pass
            
    return signer, verify

table = list()

for dir_name in os.listdir("."):
    if len(dir_name) == 64 and os.path.isdir(dir_name):
        for file_name in os.listdir(dir_name):
            file_path = os.path.join(dir_name, file_name)
            if file_path.endswith(".exe") and os.path.isfile(file_path):
                signer, verify = get_signature_status(file_path)
                print("[*] {} {} {} {}".format(signer, file_name, verify, dir_name))
                table_item = {"signer": signer, "file_name": file_name, "verify": verify, "dir_name": dir_name}
                table.append(table_item)
                continue
                
table.sort(key=lambda x:x['signer'])

readme = "# dll-hijack-collection\n"
readme += "|Signer|File|Verify|Vulnerability|\n"
readme += "|:-|:-|:-|:-|\n"

non_trusted = ""

for item in table:
    item_row = "|{}|{}|{}|[Link]({})|\n".format(item["signer"], item["file_name"], item["verify"], item["dir_name"])
    if item["signer"] == "N/A":
        non_trusted += item_row
        continue
    readme += item_row
readme += non_trusted
            
with open("README.md", "w") as f:
    f.write(readme)