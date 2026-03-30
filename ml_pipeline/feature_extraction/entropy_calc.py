import math
from collections import Counter

def calculate_shannon_entropy(data_buffer: bytes)-> float:
    
    if not data_buffer:
        return 0.0
    
    buffer_length = len(data_buffer)
    byte_frequencies = Counter(data_buffer)    #Counter returns the number of times each *ASCII* char has repeated in the data_buffer
    
    entropy = 0.0
    for count in byte_frequencies.values():
        probability = count / buffer_length
        entropy -= probability * math.log2(probability)
        
    return entropy


#simulation
if __name__ == "__main__":
    benign_buffer = b'\x00'*65536
    
    import os
    
    encrypted_buffer = os.urandom(65536)
    print(f"Benign Buffer Entropy: {calculate_shannon_entropy(benign_buffer)}");
    print(f"Encrypted Buffer Entropy: {calculate_shannon_entropy(encrypted_buffer)}");