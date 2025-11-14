import heapq
from collections import Counter

class HuffmanNode:
    def __init__(self, char, freq):
        self.char = char
        self.freq = freq
        self.left = None
        self.right = None
    
    def __lt__(self, other):
        return self.freq < other.freq

class Huffman:
    @staticmethod
    def _build_tree(freq_table):
        heap = [HuffmanNode(char, freq) for char, freq in freq_table.items()]
        heapq.heapify(heap)
        
        while len(heap) > 1:
            left = heapq.heappop(heap)
            right = heapq.heappop(heap)
            
            merged = HuffmanNode(char=None, freq=left.freq + right.freq)
            merged.left = left
            merged.right = right
            
            heapq.heappush(heap, merged)
        
        return heap[0] if heap else None
    
    @staticmethod
    def _generate_codes(root, current_code="", codes=None):
        if codes is None:
            codes = {}
        
        if root is None:
            return codes
        
        if root.char is not None:
            codes[root.char] = current_code if current_code else "0"
        
        Huffman._generate_codes(root.left, current_code + "0", codes)
        Huffman._generate_codes(root.right, current_code + "1", codes)
        
        return codes
    
    @staticmethod
    def compress(text: str) -> dict:
        if not text:
            return {
                'success': False,
                'error': 'Texto vacio'
            }
        
        freq_table = Counter(text)
        tree = Huffman._build_tree(freq_table)
        codes = Huffman._generate_codes(tree)
        compressed_bits = ''.join([codes[char] for char in text])
        
        original_size = len(text) * 8
        compressed_size = len(compressed_bits)
        ratio = ((original_size - compressed_size) / original_size * 100) if original_size > 0 else 0
        
        return {
            'success': True,
            'original_text': text,
            'compressed_text': compressed_bits,
            'codes': codes,
            'original_size': original_size,
            'compressed_size': compressed_size,
            'compression_ratio': ratio,
            'tree': tree
        }
    
    @staticmethod
    def decompress(compressed_bits: str, tree) -> str:
        if not compressed_bits or not tree:
            return ""
        
        decompressed = []
        current_node = tree
        
        for bit in compressed_bits:
            if bit == '0':
                current_node = current_node.left if current_node.left else current_node
            else:
                current_node = current_node.right if current_node.right else current_node
            
            if current_node.char is not None:
                decompressed.append(current_node.char)
                current_node = tree
        
        return ''.join(decompressed)