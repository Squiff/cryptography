import os

class AES:

    irreducible_polynomial = 0b100011011 # x8 + x4 + x3 + x +1

    mix_matrix = (  (2, 3, 1, 1),
                    (1, 2, 3, 1),
                    (1, 1, 2, 3), 
                    (3, 1, 1, 2))

    mix_matrix_inv = (  (14, 11, 13, 9),
                        (9, 14, 11, 13),
                        (13, 9, 14, 11),
                        (11, 13, 9, 14))
    
    sbox = (
            0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
            0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
            0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
            0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
            0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
            0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
            0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
            0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
            0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
            0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
            0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
            0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
            0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
            0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
            0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
            0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
            )

    sbox_inv = (
                0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
                0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
                0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
                0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
                0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
                0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
                0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
                0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
                0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
                0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
                0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
                0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
                0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
                0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
                0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
                0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
                )

    def __init__(self, key):
        self.plaintext = bytes()
        self.ciphertext = bytes()
        self.state_bytes = bytes()
        self.state = None
        self.key = key
        self.rounds = int((len(key)/4) + 6)
        self.round_keys = self.key_schedule()

    def encrypt(self):
        """ encrypt the plaintext """ 
        state_end = 16
        self.ciphertext = bytes()   # reset
        message_len = len(self.plaintext)

        #loop for each complete 16 bytes
        while state_end <= message_len:
            self.state_bytes = self.plaintext[state_end - 16 :state_end]  
            self.state = self.to_matrix(self.state_bytes)
            self.encrypt_state()
            self.ciphertext += self.state_bytes
            state_end += 16

        # last round for the final padded 16 byte message
        self.state_bytes = self.get_padding()
        self.state = self.to_matrix(self.state_bytes)
        self.encrypt_state()
        self.ciphertext += self.state_bytes 

    def decrypt(self):
        """ decrypt the ciphertext """ 
        state_end = 16
        self.plaintext = bytes()   # reset
        message_len = len(self.ciphertext)

        #loop for each complete 16 bytes
        while state_end <= message_len:
            self.state_bytes = self.ciphertext[state_end - 16 :state_end]
            self.state = self.to_matrix(self.state_bytes)
            self.decrypt_state()
            self.plaintext += self.state_bytes
            state_end += 16

        # remove the massage padding
        self.strip_padding()

    def get_padding(self):
        """ returns the (padded) last 16 bytes of the plaintext message """
        plain_len = len(self.plaintext)
        padding_len = 16 - (plain_len % 16)
        unpadded_plaintext = self.plaintext[-(plain_len % 16):]
        
        if padding_len == 0:
            padding = bytes([16]) * 16
        else:
            padding = unpadded_plaintext + (bytes([padding_len]) * padding_len)

        return padding

    def strip_padding(self):
        "remove padding from plaintext"
        padding_len = self.plaintext[-1]
        self.plaintext = self.plaintext[:-padding_len]


    @staticmethod
    def to_matrix(in_bytes):
        '''       
        convert list-like into a Nx4 byte matrix
        [[0, 1, 2, 3], [4, 5, 6, 7], [8, 9, 10, 11], [12, 13, 14, 15]]
        '''
        return [list(in_bytes[(4*i):(4*i)+4]) for i in range(len(in_bytes)//4)]

    @staticmethod
    def to_bytes(matrix):
        """ convert 2D matrix of ints to bytes """
        output = bytes()
        for i in matrix:
            output += bytes(i)
        
        return output

    @classmethod
    def ff_multiply(cls, val1, val2):
        '''
        finite field multiplication. 
        polynomial multiplication mod (x8 + x4 + x3 + x +1)
        '''
        carry_mask = 0b100000000 # mask to check if we have carried into a 9th bit
        total = 0
        temp_val2 = val2 # temp value for left shifting
        temp_val1 = val1 # temp value for right shifting

        while temp_val1 != 0:

            # check if we have carried, if so, reduce using XOR
            if temp_val2 & carry_mask > 0: 
                temp_val2 = temp_val2 ^ cls.irreducible_polynomial # 0b100011011
            
            # check right most bit
            if temp_val1 & 1 == 1:
                total = total ^ temp_val2   

            temp_val1 = temp_val1 >> 1 # shift to look at next bit
            temp_val2 = temp_val2 << 1 # shift since we will be multiplying by higher degree polynomial

        return total

    def add_round_key(self, round_key):

        round_key = self.to_matrix(round_key)

        for i in range(4):
            for j in range(4):
                self.state[i][j] = self.state[i][j] ^ round_key[i][j]

    def sub_bytes(self, inverse = 0):
        if inverse == 0:
            sbox = self.sbox
        else:
            sbox = self.sbox_inv

        for i in range(4):
            for j in range(4):
                self.state[i][j] = sbox[self.state[i][j]]

    def shift_bytes(self, in_bytes, shift):
        """ rotate bytes by selected number of positions """
        return in_bytes[shift:] + in_bytes[:shift]

    def shift_rows(self, inverse = 0):
        if inverse == 0:
            inverse_multiplier = 1
        else:
            inverse_multiplier = -1

        for i in range(1,4):
            state_row = [column[i] for column in self.state]
            shift_by = i * inverse_multiplier
            state_row = self.shift_bytes(state_row, shift_by)
            
            for pos, val in enumerate(state_row):
                self.state[pos][i] = val

    def mix_columns(self, inverse = 0):

        if inverse == 0:
            matrix = self.mix_matrix
        else:
            matrix = self.mix_matrix_inv

        for i in range(4):
            new_values = []
            for j in range(4):
                results = []
                total = 0

                for m in range(4):
                    results.append(self.ff_multiply(matrix[j][m], self.state[i][m]))

                for result in results:
                    total = total ^ result

                new_values.append(total)

            self.state[i] = new_values

    def round_constants(self):
        '''
        generate the round constants used in the key schedule
        return dict {round: constant}
        '''
        round_constants = {}
        constant_id = 1
        constant_value = 1
        round_constants[constant_id] = constant_value

        for constant_id in range(2, self.rounds + 1):
            constant_value = self.ff_multiply(2, constant_value)
            round_constants[constant_id] = constant_value

        return round_constants     

    def key_schedule(self):
        '''
        generate round keys
        '''
        round_keys = self.to_matrix(self.key)
        round_constants = self.round_constants()
        key_len = len(self.key) * 8                          # bit length of key
        block_count = int(len(self.key)/4)                   # number of 4 byte blocks
        block_pos = block_count                         # starting column is the first new column
        last_block_pos = (self.rounds + 1) * 4                # stop condition

        while block_pos < last_block_pos:
            block1 = round_keys[block_pos - 1]
            block2 = round_keys[block_pos - block_count]

            # first word every block, apply word rot & sub bytes
            if block_pos % block_count == 0: 
                new_block = self.shift_bytes(block1, 1)                           # word rot
                new_block = [self.sbox[byte] for byte in new_block]               # sub bytes
                round_constant = round_constants[block_pos//block_count]          # add (XOR) round constant to first bytes
                new_block[0] = new_block[0] ^ round_constant              
                new_block = [new_block[i] ^ block2[i] for i in range(4)]          # add each byte  
            elif block_pos % block_count == 4 and key_len == 256:                 # variant for 256-bit key
                new_block = [self.sbox[byte] for byte in block1]                  # sub bytes
                new_block = [new_block[i] ^ block2[i] for i in range(4)]          # add with previous block
            else:
                new_block = [block1[i] ^ block2[i] for i in range(4)]             # add each byte

            round_keys.append(new_block)
            block_pos += 1

        # flatten the matrix and group each 128 bit round key {1:roundkey1, 2:roundkey2, 3:roundkey3 ....}
        round_keys_1d = [byte for block in round_keys for byte in block]
        round_keys_dict = {}
        for i in range(len(round_keys_1d) // 16):
            round_keys_dict[i] = bytes(round_keys_1d[i*16:(i+1)*16])

        return round_keys_dict           

    def encrypt_state(self):
        """ encrypt the current 128 bit state (self.state) """
        self.add_round_key(self.round_keys[0])

        round_id = 1
        while round_id < self.rounds:
            self.sub_bytes()
            self.shift_rows()
            self.mix_columns()
            self.add_round_key(self.round_keys[round_id])              
            round_id += 1

        self.sub_bytes()
        self.shift_rows()       
        self.add_round_key(self.round_keys[round_id])

        self.state_bytes = self.to_bytes(self.state)

    def decrypt_state(self):
        """ decrypt the current 128 bit state (self.state) """
        round_id = self.rounds

        self.add_round_key(self.round_keys[round_id])
        self.shift_rows(inverse = 1)
        self.sub_bytes(inverse = 1)
        round_id -= 1

        while round_id > 0:
            self.add_round_key(self.round_keys[round_id])
            self.mix_columns(inverse = 1)
            self.shift_rows(inverse = 1)
            self.sub_bytes(inverse = 1)
            round_id -= 1

        self.add_round_key(self.round_keys[round_id])
        self.state_bytes = self.to_bytes(self.state)
       
    @staticmethod
    def generate_key(size = 128):
        if size not in (128, 192, 256):
            raise ValueError ('Invalid Key Length. Should be 128, 192 or 256 bits')

        return os.urandom(int(size/8))