import math
import os
import time
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

def calculate_chi_square(data_buffer: bytes) -> float:

    if not data_buffer:
        return 0.0

    buffer_length = len(data_buffer)
    expected_frequency = buffer_length / 256.0
    byte_frequencies = Counter(data_buffer)

    chi_square_stat = 0.0

    for i in range(256):
        observed_frequency = byte_frequencies.get(i, 0);
        chi_square_stat += ((observed_frequency - expected_frequency) ** 2)/ expected_frequency

    return chi_square_stat

def calculate_monobit(data_buffer: bytes) -> float:

    if not data_buffer:
        return 0.0
    
    ones_count = sum(bin(byte).count('1') for byte in data_buffer)
    total_bits = len(data_buffer) * 8
    proportion = ones_count / total_bits
    distance_from_prefect_random = abs(0.5 - proportion)

    return distance_from_prefect_random


def calculate_poker_test(data_buffer: bytes) -> float:
    nibble_counts = [0]* 16

    for byte in data_buffer:
        nibble_counts[byte >> 4] += 1
        nibble_counts[byte & 0x0F] += 1

    N = len(data_buffer) * 2
    if N == 0:
        return 0.0

    sum_sq = sum(count* count for count in nibble_counts)
    poker_stat = (16.0/N)* sum_sq - N
    
    return poker_stat
    

def calculate_cumulative_sums(data_buffer: bytes) -> float:
    if not data_buffer:
        return 0.0

    current_sum = 0
    max_excursion = 0

    for byte in data_buffer:
        for i in range(8):
            bit = (byte >> i) & 1
            current_sum += 1 if bit == 1 else -1
            
            if(abs(current_sum) > max_excursion):
                max_excursion = abs(current_sum)

    total_bits = len(data_buffer) * 8

    return max_excursion / total_bits


def extract_mac_metadata(file_path: str) -> float:
    try:
        stat_info = os.stat(file_path)
        m_time = stat_info.st_mtime
        a_time = stat_info.st_atime
        time_delta = abs(m_time - a_time)
        return time_delta

    except Exception:
        return 100.0
#simulation

if __name__ == "__main__":
    benign_buffer = b'\x00'*65536
    encrypted_buffer = os.urandom(65536)

    print(f"Benign Buffer Entropy: {calculate_shannon_entropy(benign_buffer)}");
    print(f"Encrypted Buffer Entropy: {calculate_shannon_entropy(encrypted_buffer)}");