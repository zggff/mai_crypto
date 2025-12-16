import BigInt
import Foundation

public struct SHA256 {
    private static let k: [UInt32] = [
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]
    
    private var h: [UInt32] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    ]
    
    private var data: [UInt8] = []
    private var length: UInt64 = 0
    
    public init() {}
    
    public mutating func update(_ data: [UInt8]) {
        self.data.append(contentsOf: data)
        length += UInt64(data.count) * 8
    }
    
    public mutating func finalize() -> [UInt8] {
        var padded = data
        padded.append(0x80)
        
        while (padded.count * 8) % 512 != 448 {
            padded.append(0x00)
        }
        
        let lengthBytes = withUnsafeBytes(of: length.bigEndian) { Array($0) }
        padded.append(contentsOf: lengthBytes)
        
        for chunk in padded.chunked(into: 64) {
            process(chunk: chunk)
        }
        
        var result: [UInt8] = []
        for value in h {
            result.append(contentsOf: withUnsafeBytes(of: value.bigEndian) { Array($0) })
        }
        
        return result
    }
    
    private mutating func process(chunk: [UInt8]) {
        var w = [UInt32](repeating: 0, count: 64)
        
        for i in 0..<16 {
            let index = i * 4
            w[i] = UInt32(chunk[index]) << 24 |
                   UInt32(chunk[index + 1]) << 16 |
                   UInt32(chunk[index + 2]) << 8 |
                   UInt32(chunk[index + 3])
        }
        
        for i in 16..<64 {
            let s0 = rightRotate(w[i-15], 7) ^ rightRotate(w[i-15], 18) ^ (w[i-15] >> 3)
            let s1 = rightRotate(w[i-2], 17) ^ rightRotate(w[i-2], 19) ^ (w[i-2] >> 10)
            w[i] = w[i-16] &+ s0 &+ w[i-7] &+ s1
        }
        
        var a = h[0], b = h[1], c = h[2], d = h[3]
        var e = h[4], f = h[5], g = h[6], hVal = h[7]
        
        for i in 0..<64 {
            let s1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25)
            let ch = (e & f) ^ (~e & g)
            let temp1 = hVal &+ s1 &+ ch &+ SHA256.k[i] &+ w[i]
            let s0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22)
            let maj = (a & b) ^ (a & c) ^ (b & c)
            let temp2 = s0 &+ maj
            
            hVal = g
            g = f
            f = e
            e = d &+ temp1
            d = c
            c = b
            b = a
            a = temp1 &+ temp2
        }
        
        h[0] = h[0] &+ a
        h[1] = h[1] &+ b
        h[2] = h[2] &+ c
        h[3] = h[3] &+ d
        h[4] = h[4] &+ e
        h[5] = h[5] &+ f
        h[6] = h[6] &+ g
        h[7] = h[7] &+ hVal
    }
    
    private func rightRotate(_ value: UInt32, _ count: Int) -> UInt32 {
        return (value >> count) | (value << (32 - count))
    }
    
    public static func hash(_ data: [UInt8]) -> [UInt8] {
        var sha = SHA256()
        sha.update(data)
        return sha.finalize()
    }
}

public struct HMAC {
    public enum Hash {
        case sha256
        
        var blockSize: Int {
            switch self {
            case .sha256: return 64
            }
        }
        
        var outputSize: Int {
            switch self {
            case .sha256: return 32
            }
        }
        
        func hash(_ data: [UInt8]) -> [UInt8] {
            switch self {
            case .sha256: return SHA256.hash(data)
            }
        }
    }
    
    let hash: Hash
    
    public init(hash: Hash = .sha256) {
        self.hash = hash
    }
    
    public func authenticate(key: [Byte], data: [Byte]) -> [Byte] {
        let blockSize = hash.blockSize
        
        var normalizedKey = key
        if normalizedKey.count > blockSize {
            normalizedKey = hash.hash(normalizedKey)
        }
        
        if normalizedKey.count < blockSize {
            normalizedKey.append(contentsOf: [UInt8](repeating: 0, count: blockSize - normalizedKey.count))
        }
        
        let opad = xor(key: normalizedKey, pad: 0x5c)
        let ipad = xor(key: normalizedKey, pad: 0x36)
        
        var innerData = ipad
        innerData.append(contentsOf: data)
        let innerHash = hash.hash(innerData)
        
        var outerData = opad
        outerData.append(contentsOf: innerHash)
        
        return hash.hash(outerData)
    }
    
    private func xor(key: [Byte], pad: UInt8) -> [Byte] {
        return key.map { $0 ^ pad }
    }
}

public struct HKDF {
    public enum Error: Swift.Error {
        case invalidOutputLength
        case extractFailed
        case expandFailed
    }
    
    private let hmac: HMAC
    
    public init(hash: HMAC.Hash = .sha256) {
        self.hmac = HMAC(hash: hash)
    }
    
    public func extract(salt: [Byte]?, ikm: [Byte]) -> [Byte] {
        let salt = salt ?? [Byte](repeating: 0, count: hmac.hash.outputSize)
        return hmac.authenticate(key: salt, data: ikm)
    }
    
    public func expand(prk: [Byte], info: [Byte], length: Int) throws -> [Byte] {
        guard length > 0 && length <= 255 * hmac.hash.outputSize else {
            throw Error.invalidOutputLength
        }
        
        var output: [Byte] = []
        var t: [Byte] = []
        
        let n = Int(ceil(Double(length) / Double(hmac.hash.outputSize)))
        
        for i in 1...n {
            var input = t
            input.append(contentsOf: info)
            input.append(UInt8(i))
            
            t = hmac.authenticate(key: prk, data: input)
            output.append(contentsOf: t)
        }
        
        return Array(output.prefix(length))
    }
    
    public func deriveKey(salt: [Byte]?, ikm: [Byte], info: [Byte], length: Int) throws -> [Byte] {
        let prk = extract(salt: salt, ikm: ikm)
        return try expand(prk: prk, info: info, length: length)
    }
}

extension Array where Element == UInt8 {
    func chunked(into size: Int) -> [[Element]] {
        stride(from: 0, to: count, by: size).map {
            Array(self[$0..<Swift.min($0 + size, count)])
        }
    }
}
