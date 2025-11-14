class FNV1:
    FNV1_32_PRIME = 0x01000193
    FNV1_32_OFFSET = 0x811c9dc5
    
    @staticmethod
    def calculate_hash(text: str) -> dict:
        hash_value = FNV1.FNV1_32_OFFSET
        
        for byte in text.encode("utf-8"):
            hash_value = (hash_value * FNV1.FNV1_32_PRIME) & 0xffffffff
            hash_value = hash_value ^ byte
        
        return {
            "decimal": hash_value,
            "hex": f"{hash_value:08x}",
            "original_text": text
        }