from pypbc import Parameters,Pairing,Element,G1,G2,GT,Zr
params = Parameters(qbits = 64, rbits = 20)
pairing=Pairing(params)

bitsNum = 32
upbound = 2 ** (bitsNum)
dimension = 10#隐私向量的维度
DHp = 228109676843431#generate_big_prime(bitsNum)
     #
DHg = 3#generatePrimitiveRoot(DHp)
localhost = '127.0.0.1'
server_port = 8080
nonce = Element.random( pairing, G1 )
