from bardapi import Bard
import os
import sys
import json


token="XAjx2Qs4ElonIfjWcFo0pE5Mryy_7BDjfNUWw4e_JjuqwQXi_qFZRIx9ZUEmPz6ha8XRPw."

#cloud_attacks = Bard(token=token).get_answer("Provide list of cloud top 10 ATT&CK tactics with ID, techniques with ID, sub-techniques with ID that are attacked also give me as a JSON data")['content']
# cloud_attacks = Bard(token=token).get_answer('''Provide list of cloud top 10 ATT&CK tactics with ID, techniques with ID, sub-techniques with ID that are attacked also give me as a JSON data with values "1":[{"technique": ","technique_name":" " , "tactic":" ","tactics_name":" ","mitigations":" "}]''')['content']
# cloud_attacks = Bard(token=token).get_answer('''Provide list of cloud top ATT&CK tactics and also give me as a JSON data with this format {technique_id, {subtechnique: [sub_technique_id] } }''')['content']
# cloud_attacks = Bard(token=token).get_answer(''' give me just the ATT&CK tecnique is that are mapped for aws foundational controls in cis''')['content']
# cloud_attacks = Bard(token=token).get_answer('''give a list of cloud top ATT&CK technique_id,subtechnique_id }''')['content']
# cloud_attacks = Bard(token=token).get_answer('''elaborate on ATT&CK techniques T1190,T1210,T1530''')['content']
cloud_attacks = Bard(token=token).get_answer('''repeat what i say "T1530,T1190,T1210" ''')['content']



response_json = json.dumps(cloud_attacks)

sys.stdout.write(response_json)
sys.stdout.flush()

# with open('output.txt','w') as file:
#     file.write(cloud_attacks)



