import hashlib
import os
# import json
import ujson
from time import time
from urllib.parse import urlparse
from uuid import uuid4
import base64
import requests

from Crypto.PublicKey import RSA 
from Crypto.Signature import pss 
from Crypto.Hash import SHA256

class Blockchain:
    def __init__(self):
        self.current_transactions = []
        self.chain = []
        self.nodes = set()

        # Create the genesis block
        self.new_block({},None)

    def register_node(self, address):
        """
        Add a new node to the list of nodes

        :param address: Address of node. Eg. 'http://192.168.0.5:5000'
        """

        parsed_url = urlparse(address)
        if parsed_url.netloc:
            self.nodes.add(parsed_url.netloc)
        elif parsed_url.path:
            # Accepts an URL without scheme like '192.168.0.5:5000'.
            self.nodes.add(parsed_url.path)
        else:
            raise ValueError('Invalid URL')
    def valid(self):
        Blockchain.valid_chain(self.chain)
    @staticmethod
    def valid_chain(chain):
        """
        Determine if a given blockchain is valid

        :param chain: A blockchain
        :return: True if valid, False if not
        """
        last_hash = None
        for block in chain:
            if block.previous_hash != last_hash:
                return False
            last_hash = block.hash()

        return True

    def new_block(self, data, previous_hash):
        """
        Create a new Block in the Blockchain

        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """

        block = Block(data,previous_hash)

        # Reset the current list of transactions
        self.current_transactions = []

        self.chain.append(block)
        return block
    @property
    def last_block(self):
        return self.chain[-1]

class Block():
    #data is an empty Dictionary filled by key value data
    def __init__(self,data={},previous_hash=None):
        self.data = data
        self.previous_hash = previous_hash
        if 'previous_hash' in self.data and self.previous_hash is None:
            self.previous_hash = data['previous_hash']
    def hash(self):
        if self.previous_hash is not None:
            self.data['previous_hash'] = self.previous_hash
        keys = sorted(self.data.keys())
        keyString = ''.join(keys)
        valueString = ''
        for key in keys:
            # print(key)
            valueString += str(self.data[key])
        data_hash = keyString+valueString
        return hashlib.sha256(data_hash.encode('utf-8')).hexdigest()
    def hash_json(self):# i do not like this kind of hash as json formatting and order are ment to be changed
        """
        Creates a SHA-256 hash of a Block

        :param block: Block
        """
        if self.previous_hash is not None:
            self.data['previous_hash'] = self.previous_hash
        # We must make sure that the Dictionary is Ordered, or we'll have inconsistent hashes
        block_string = ujson.dumps(self.data, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()
    def asJSON(self):
        return ujson.dumps(self.data)
    @staticmethod
    def loadJSON(json_data):
        return Block(json_data,json_data['previous_hash'])
class RSABlock():
    def __init__(self,data={},private_file='private.pem',public_file='public.pem'):
        self.private        = None
        self.public         = None
        self.private_file   = private_file
        self.public_file    = public_file
        self.load()
        self.save_root_block()
    def block(self,root_block_path='root_block.json'):
        #both are equal or None
        if self.private == self.public:
            return None
        root_block = self.load_root_block()
        if root_block != False:
            return root_block
        return Block(data={
            'key': str(self.public.exportKey("PEM"),'utf-8'),
            #signature takes time into considration so do it every time
            'key_hash_sign': self.signature()
        })
    def load_root_block(self,root_block_path='root_block.json'):
        if os.path.isfile(root_block_path):
            with open(root_block_path, "r") as json_file:
                jdata = ujson.load(json_file)    
            return Block(data=jdata)
        return False
    def save_root_block(self,root_block_path='root_block.json'):
        root_json = self.block().asJSON()
        with open(root_block_path, "w") as json_file:
            json_file.write(root_json)
    def save(self,private_file='private.pem',public_file='public.pem'):
        with open(private_file, "wb") as key_file:
            key_file.write(self.private.exportKey("PEM"))
        with open(public_file, "wb") as key_file:
            key_file.write(self.public.exportKey("PEM"))
    def load(self,private_file='private.pem',public_file='public.pem'):
        if not (os.path.isfile(private_file) and os.path.isfile(public_file)):
            self.private,self.public = RSABlock.generate_RSA()
            self.save()
        else:
            with open(private_file, "rb") as key_file:
                self.private = RSA.import_key(key_file.read())
            with open(public_file, "rb") as key_file:
                self.public = RSA.import_key(key_file.read())
    def signature(self):
        singer = pss.new(self.private)
        sn_bytes = singer.sign(SHA256.new(self.public.exportKey('PEM')))
        return str(base64.b64encode(sn_bytes),'utf-8')
    def verifier(self,signature):
        sn_str = base64.b64decode(signature)
        verifier = pss.new(self.public)
        try:
            verifier.verify(SHA256.new(self.public.exportKey('PEM')),sn_str)
            return True
        except (ValueError, TypeError):
            return False
    @staticmethod
    def verifier_key(public,signature):
        sn_str = base64.b64decode(signature)
        verifier = pss.new(public)
        try:
            verifier.verify(SHA256.new(public.exportKey('PEM')),sn_str)
            return True
        except (ValueError, TypeError):
            return False
    @staticmethod
    def generate_RSA(bits=2048):
        private_key = RSA.generate(bits, e=65537) 
        return private_key, private_key.publickey()
class blockManager():
    #blocks manager class to store and retrive blocks in memory dictionary with IO backup
    def __init__(self):
        self.blocks = {}
    def addBlock(self,block):
        block_hash = block.hash()
        if block_hash not in self.blocks:
            self.blocks[block_hash] = {}
            self.blocks[block_hash]['sub_blocks'] = []
        self.blocks[block_hash]['data'] = block
        if block.previous_hash is not None:
            if block.previous_hash not in self.blocks:
                self.blocks[block.previous_hash] = {}
                self.blocks[block.previous_hash]['sub_blocks'] = []
            self.blocks[block.previous_hash]['sub_blocks'].append(block)
    def save(self,blocks_path='blocks.json'):
        with open(blocks_path, "w") as json_file:
            json_file.write(ujson.dumps(self.blocks))
    def asJSON(self):
        return ujson.dumps(self.blocks)
    def asBJSON(self):
        data = []
        for hash_str in self.blocks:
            sub_hashes = []
            for sub_block in self.blocks[hash_str]['sub_blocks']:
                sub_hashes.append(sub_block.hash())
            data.append({
                'hash':self.blocks[hash_str]['data'].hash(),
                'data':self.blocks[hash_str]['data'].data,
                'previous_hash':self.blocks[hash_str]['data'].previous_hash,
                'sub_hashes':sub_hashes
            })
        return ujson.dumps(data)