import hashlib

# The secondary key for tail XOR (Charlie is the d...)
TAIL_KEY = b"Charlie is the designer of P2P!!"

# The constant C derived from f(0) using LD_PRELOAD
XOR_CONSTANT = bytes.fromhex('6e2e8d8c40d040ca2d6d280c40e4cad8')

# Pure Python implementation array (ENCODE)
ENCODE_BIT_MAP = [
    112, 77, 78, 79, 80, 81, 82, 83, 84, 93, 94, 95, 64, 65, 66, 67, 
    68, 85, 86, 87, 88, 89, 90, 91, 92, 105, 106, 107, 108, 109, 110, 111, 
    100, 101, 102, 103, 104, 121, 122, 123, 124, 125, 126, 127, 96, 69, 70, 71, 
    72, 73, 74, 75, 76, 113, 114, 115, 116, 117, 118, 119, 120, 97, 98, 99, 
    40, 29, 30, 31, 0, 1, 2, 3, 4, 13, 14, 15, 16, 17, 18, 19, 
    20, 5, 6, 7, 8, 9, 10, 11, 12, 33, 34, 35, 36, 37, 38, 39, 
    52, 53, 54, 55, 56, 21, 22, 23, 24, 25, 26, 27, 28, 41, 42, 43, 
    44, 45, 46, 47, 48, 57, 58, 59, 60, 61, 62, 63, 32, 49, 50, 51
]

DECODE_BIT_MAP = [
    68, 69, 70, 71, 72, 81, 82, 83, 84, 85, 86, 87, 88, 73, 74, 75, 
    76, 77, 78, 79, 80, 101, 102, 103, 104, 105, 106, 107, 108, 65, 66, 67, 
    124, 89, 90, 91, 92, 93, 94, 95, 64, 109, 110, 111, 112, 113, 114, 115, 
    116, 125, 126, 127, 96, 97, 98, 99, 100, 117, 118, 119, 120, 121, 122, 123, 
    12, 13, 14, 15, 16, 45, 46, 47, 48, 49, 50, 51, 52, 1, 2, 3, 
    4, 5, 6, 7, 8, 17, 18, 19, 20, 21, 22, 23, 24, 9, 10, 11, 
    44, 61, 62, 63, 32, 33, 34, 35, 36, 25, 26, 27, 28, 29, 30, 31, 
    0, 53, 54, 55, 56, 57, 58, 59, 60, 37, 38, 39, 40, 41, 42, 43
]

def transcode_encode(data: bytes) -> bytes:
    """Encode TUTK packets (TransCodePartial)"""
    result = bytearray(len(data))
    full_blocks = (len(data) // 16) * 16
    for offset in range(0, full_blocks, 16):
        in_block = data[offset:offset+16]
        out_block = bytearray(16)
        for b in range(128):
            if in_block[b // 8] & (1 << (b % 8)):
                out_bit_idx = ENCODE_BIT_MAP[b]
                out_block[out_bit_idx // 8] |= (1 << (out_bit_idx % 8))
        for i in range(16):
            result[offset + i] = out_block[i] ^ XOR_CONSTANT[i]
            
    for i in range(full_blocks, len(data)):
        result[i] = data[i] ^ TAIL_KEY[(i - full_blocks) % len(TAIL_KEY)]
        
    return bytes(result)

def transcode_decode(data: bytes) -> bytes:
    """Decode TUTK packets (TransCodePartial reverse)"""
    result = bytearray(len(data))
    full_blocks = (len(data) // 16) * 16
    for offset in range(0, full_blocks, 16):
        in_block = data[offset:offset+16]
        xored = bytearray(a ^ b for a, b in zip(in_block, XOR_CONSTANT))
        out_block = bytearray(16)
        for b in range(128):
            if xored[b // 8] & (1 << (b % 8)):
                out_bit_idx = DECODE_BIT_MAP[b]
                out_block[out_bit_idx // 8] |= (1 << (out_bit_idx % 8))
        result[offset:offset+16] = out_block
        
    for i in range(full_blocks, len(data)):
        result[i] = data[i] ^ TAIL_KEY[(i - full_blocks) % len(TAIL_KEY)]
        
    return bytes(result)
