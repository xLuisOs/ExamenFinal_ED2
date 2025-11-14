from fnv1 import FNV1
from huffman import Huffman
from rsa_manager import RSAManager

#Luis 
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    WHITE = '\033[97m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

class SecureMessagingSystem:
    def __init__(self):
        self.message = ""
        self.message_hash = None
        self.compressed_data = None
        self.rsa_manager = RSAManager()
        self.signature = None
        self.transmitted_message = None
        self.transmitted_signature = None
        self.transmitted_public_key = None
        self.transmitted_tree = None
    
    def show_menu(self):
        print("\n" + "="*60)
        print(f"{Colors.CYAN}{Colors.BOLD}       SISTEMA DE MENSAJERIA SEGURA{Colors.ENDC}")
        print("="*60)
        print(f"\n{Colors.WHITE}1  Ingresar mensaje")
        print("2  Calcular hash FNV-1")
        print("3  Comprimir mensaje")
        print("4  Firmar el hash con la clave privada RSA")
        print("5  Simular envio (mensaje comprimido + firma + clave publica)")
        print("6  Descomprimir y verificar firma (clave publica)")
        print("7  Mostrar si el mensaje es autentico o alterado")
        print(f"0  Salir{Colors.ENDC}")
        print("\n" + "="*60)
    
    def ingresar_mensaje(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}INGRESAR MENSAJE{Colors.ENDC}")
        print("─"*60)
        
        self.message = input(f"\n{Colors.WHITE}Ingrese el mensaje a enviar: {Colors.ENDC}").strip()
        
        if not self.message:
            print(f"{Colors.RED}Error: El mensaje no puede estar vacio{Colors.ENDC}")
            return
        
        print(f"\n{Colors.GREEN}Mensaje ingresado exitosamente{Colors.ENDC}")
        print(f"{Colors.WHITE}Contenido: '{self.message}'")
        print(f"Longitud: {len(self.message)} caracteres{Colors.ENDC}")
        
        self.message_hash = None
        self.compressed_data = None
        self.signature = None
        self.transmitted_message = None
    
    def calcular_hash(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}CALCULAR HASH FNV-1{Colors.ENDC}")
        print("─"*60)
        
        if not self.message:
            print(f"{Colors.RED}Error: Primero debe ingresar un mensaje (Opcion 1){Colors.ENDC}")
            return
        
        self.message_hash = FNV1.calculate_hash(self.message)
        
        print(f"\n{Colors.GREEN}Hash calculado exitosamente{Colors.ENDC}")
        print(f"{Colors.WHITE}Hash (Decimal): {self.message_hash['decimal']}")
        print(f"Hash (Hexadecimal): {self.message_hash['hex']}{Colors.ENDC}")
    
    def comprimir_mensaje(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}COMPRIMIR MENSAJE CON HUFFMAN{Colors.ENDC}")
        print("─"*60)
        
        if not self.message:
            print(f"{Colors.RED}Error: Primero debe ingresar un mensaje (Opcion 1){Colors.ENDC}")
            return
        
        print(f"\n{Colors.WHITE}Comprimiendo mensaje...{Colors.ENDC}")
        self.compressed_data = Huffman.compress(self.message)
        
        if not self.compressed_data['success']:
            print(f"{Colors.RED}Error: {self.compressed_data['error']}{Colors.ENDC}")
            return
        
        print(f"\n{Colors.GREEN}Compresion completada{Colors.ENDC}")
        print(f"\n{Colors.WHITE}Tamaño original: {self.compressed_data['original_size']} bits")
        print(f"Tamaño comprimido: {self.compressed_data['compressed_size']} bits")
        print(f"Ratio de compresion: {self.compressed_data['compression_ratio']:.2f}%")
        print(f"\nCodigos Huffman generados:")
        
        for char, code in sorted(self.compressed_data['codes'].items()):
            print(f"   '{char}' -> {code}")
        print(Colors.ENDC)
    
    def firmar_hash(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}FIRMAR HASH CON RSA{Colors.ENDC}")
        print("─"*60)
        
        if not self.message_hash:
            print(f"{Colors.RED}Error: Primero debe calcular el hash (Opcion 2){Colors.ENDC}")
            return
        
        if not self.rsa_manager.private_key:
            print(f"\n{Colors.WHITE}Generando par de claves RSA de 512 bits...{Colors.ENDC}")
            self.rsa_manager.generate_keys(512)
            print(f"{Colors.GREEN}Claves generadas exitosamente{Colors.ENDC}")
        
        hash_to_sign = self.message_hash['hex']
        print(f"\n{Colors.WHITE}Firmando el hash: {hash_to_sign}{Colors.ENDC}")
        
        self.signature = self.rsa_manager.sign_message(hash_to_sign)
        
        print(f"\n{Colors.GREEN}Firma digital generada exitosamente{Colors.ENDC}")
        print(f"{Colors.WHITE}Firma (primeros 50 bytes en hex): {self.signature.hex()[:100]}...")
        print(f"Tamaño de la firma: {len(self.signature)} bytes")
        
        key_info = self.rsa_manager.get_key_info()
        print(f"\nINFORMACION DE LAS CLAVES:")
        print(f"   Clave publica (e): {key_info['public_key_e']}")
        print(f"   Clave publica (n): {str(key_info['public_key_n'])[:60]}...")
        print(f"   Clave privada: [CONFIDENCIAL - No se transmite]")
        print(f"   Tamaño de clave: {key_info['key_size']} bits{Colors.ENDC}")
    
    def simular_envio(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}SIMULAR ENVIO{Colors.ENDC}")
        print("─"*60)
        
        if not self.compressed_data or not self.signature:
            print(f"{Colors.RED}Error: Debe comprimir el mensaje (Opcion 3) y firmarlo (Opcion 4){Colors.ENDC}")
            return
        
        print(f"\n{Colors.WHITE}Preparando transmision...{Colors.ENDC}")
        
        self.transmitted_message = self.compressed_data['compressed_text']
        self.transmitted_signature = self.signature
        self.transmitted_public_key = self.rsa_manager.public_key
        self.transmitted_tree = self.compressed_data['tree']
        
        print(f"\n{Colors.GREEN}Datos transmitidos exitosamente{Colors.ENDC}")
        print(f"\n{Colors.WHITE}PAQUETE ENVIADO:")
        print(f"   1 Mensaje comprimido: {len(self.transmitted_message)} bits")
        print(f"   2 Firma digital: {len(self.transmitted_signature)} bytes")
        print(f"   3 Clave publica del remitente: Incluida")
        print(f"   4 Arbol de Huffman: Incluido")
        print(f"\nNOTA: La clave privada NO se transmite (permanece secreta){Colors.ENDC}")
    
    def verificar_mensaje(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}RECEPCION Y VERIFICACION{Colors.ENDC}")
        print("─"*60)
        
        if not self.transmitted_message or not self.transmitted_signature:
            print(f"{Colors.RED}Error: No hay mensaje transmitido. Use la Opcion 5 primero{Colors.ENDC}")
            return
        
        print(f"\n{Colors.WHITE}Mensaje recibido. Procesando...{Colors.ENDC}")
        
        print(f"\n{Colors.WHITE}1 Descomprimiendo mensaje...{Colors.ENDC}")
        decompressed_message = Huffman.decompress(
            self.transmitted_message, 
            self.transmitted_tree
        )
        print(f"{Colors.WHITE}   Mensaje descomprimido: '{decompressed_message}'{Colors.ENDC}")
        
        print(f"\n{Colors.WHITE}2 Calculando hash FNV-1 del mensaje recibido...{Colors.ENDC}")
        received_hash = FNV1.calculate_hash(decompressed_message)
        print(f"{Colors.WHITE}   Hash calculado: {received_hash['hex']}{Colors.ENDC}")
        
        print(f"\n{Colors.WHITE}3 Verificando firma digital con clave publica...{Colors.ENDC}")
        
        verifier = RSAManager()
        verifier.public_key = self.transmitted_public_key
        
        is_valid = verifier.verify_signature(
            received_hash['hex'], 
            self.transmitted_signature
        )
        
        print("\n" + "="*60)
        print(f"{Colors.CYAN}{Colors.BOLD}RESULTADO DE LA VERIFICACION{Colors.ENDC}")
        print("="*60)
        
        if is_valid:
            print(f"\n{Colors.GREEN}{Colors.BOLD}MENSAJE AUTENTICO Y NO MODIFICADO{Colors.ENDC}")
            print(f"\n{Colors.WHITE}Detalles:")
            print(f"   Mensaje: '{decompressed_message}'")
            print(f"   Hash: {received_hash['hex']}")
            print(f"   Firma: VALIDA")
            print(f"   Integridad: VERIFICADA")
            print(f"   Autenticidad: CONFIRMADA{Colors.ENDC}")
        else:
            print(f"\n{Colors.RED}{Colors.BOLD}ALERTA: MENSAJE ALTERADO O FIRMA NO VALIDA{Colors.ENDC}")
            print(f"\n{Colors.RED}El mensaje puede haber sido:")
            print("   Modificado durante la transmision")
            print("   Firmado con una clave incorrecta")
            print("   Corrompido")
            print(f"\n{Colors.WHITE}Mensaje recibido: '{decompressed_message}'")
            print(f"Hash calculado: {received_hash['hex']}{Colors.ENDC}")
        
        print("\n" + "="*60)
    
    def run(self):
        print(f"\n{Colors.CYAN}{Colors.BOLD}")
        print("="*60)
        print("          LUIS OSWALDO GRANADOS DE LEON")
        print("          ESTRUCTURA DE DATOS 2")
        print("="*60)
        print(Colors.ENDC)
        
        while True:
            self.show_menu()
            
            try:
                opcion = input(f"\n{Colors.WHITE}Seleccione una opcion: {Colors.ENDC}").strip()
                
                if opcion == "1":
                    self.ingresar_mensaje()
                elif opcion == "2":
                    self.calcular_hash()
                elif opcion == "3":
                    self.comprimir_mensaje()
                elif opcion == "4":
                    self.firmar_hash()
                elif opcion == "5":
                    self.simular_envio()
                elif opcion == "6" or opcion == "7":
                    self.verificar_mensaje()
                elif opcion == "0":
                    print(f"\n{Colors.GREEN}Gracias por usar el sistema")
                    print(f"Saliendo de forma segura...{Colors.ENDC}\n")
                    break
                else:
                    print(f"\n{Colors.RED}Opcion invalida. Intente nuevamente{Colors.ENDC}")
                
                input(f"\n{Colors.WHITE}Presione ENTER para continuar...{Colors.ENDC}")
                
            except KeyboardInterrupt:
                print(f"\n\n{Colors.GREEN}Saliendo del programa...{Colors.ENDC}")
                break
            except Exception as e:
                print(f"\n{Colors.RED}Error inesperado: {str(e)}{Colors.ENDC}")
                input(f"\n{Colors.WHITE}Presione ENTER para continuar...{Colors.ENDC}")

def main():
    system = SecureMessagingSystem()
    system.run()

if __name__ == "__main__":
    main()