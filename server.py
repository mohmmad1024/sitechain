from blockchain import Blockchain, Block, RSABlock ,blockManager
from flask import Flask, jsonify, request, abort ,send_file
from uuid import uuid4
import ujson

import os


keys = RSABlock()

bm = blockManager()

bm.addBlock(keys.block())

# Instantiate the Blockchain
blockchain = Blockchain()

# Instantiate the Node
app = Flask(__name__)

# Generate a globally unique address for this node
node_identifier = str(uuid4()).replace('-', '')

@app.route('/blocks', methods=['GET'])
def f_blocks():
    return jsonify(ujson.loads(bm.asJSON()))
@app.route('/b/blocks', methods=['GET'])
def f_b_blocks():
    return jsonify(ujson.loads(bm.asBJSON()))
@app.route('/blocks/add', methods=['POST'])
def f_blocks_add():
    if request.json is None:
        return abort(400)
    json_data = request.get_json()
    if 'previous_hash' not in request.json:
        return jsonify({'key1':'data1','key2':'data2','keyn':'datan','previous_hash':keys.block().hash()})
    bm.addBlock(Block(json_data,json_data['previous_hash']))
    return jsonify(ujson.loads(bm.asJSON()))
@app.route('/', methods=['GET'])
def f_root():
    return send_file('index.html')
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080,debug=True)
