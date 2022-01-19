import sys
import math
import pefile
import peutils

def Entropy(data):
	entropy = 0  
	if not data:
		return 0
	ent = 0
	for x in range(256):
		p_x = float(data.count(x))/len(data)
		if p_x > 0:
			entropy += - p_x*math.log(p_x, 2)
	return entropy

pe=pefile.PE(sys.argv[1])
print("\n=====================================")
print("   - Entropy >7.1 is suspicious")
print("=====================================\n")
for s in pe.sections:
	print (s.Name.decode('utf-8').strip('\\x00') + "\t" + str(Entropy(s.get_data())))
