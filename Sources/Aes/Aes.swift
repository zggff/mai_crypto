import Symmetric

public enum AesError: Error {
	case AesReducible
}

actor SBox: Sendable {
	let mod: Int
	init(mod: Int) throws {
		guard GF256.irreducible(mod) else {
			throw AesError.AesReducible
		}
		self.mod = mod

	}
	lazy var SBox: [Byte] = {
		var sbox = Array(repeating: Byte(0), count: 256)
		for i in 0..<256 {
			let inv = GF256.inv(Byte(i), mod: Byte(self.mod & 0xff))
			sbox[i] = Self.affineTransform(inv)
		}
		return sbox
	}()
	lazy var InvSBox: [Byte] = {
		var sbox = Array(repeating: Byte(0), count: 256)
		for i in 0..<256 {
			let inv = GF256.inv(Byte(i), mod: Byte(self.mod & 0xff))
			let aff = Self.affineTransform(inv)
			sbox[Int(aff)] = Byte(i)
		}
		return sbox
	}()

	private static func affineTransform(_ x: Byte) -> Byte {
		var result: Byte = 0
		for i in 0..<8 {
			var bit: Byte = 0
			bit ^= (x >> i) & 1
			bit ^= (x >> ((i + 4) % 8)) & 1
			bit ^= (x >> ((i + 5) % 8)) & 1
			bit ^= (x >> ((i + 6) % 8)) & 1
			bit ^= (x >> ((i + 7) % 8)) & 1
			bit ^= (0x63 >> i) & 1
			result |= (bit << i)
		}
		return result
	}
}

typealias Word = UInt32

public final class AesTransposer: EncryptTransposer {
	let sbox: SBox
	public init(mod: Int) throws {
		self.sbox = try SBox(mod: mod)
	}

	public func transpose(data: Symmetric.Block, key: Symmetric.Block) throws -> Symmetric.Block {
		return data
	}

}

public final class AesExpander: KeyExpander {
	let sBox: SBox
	static let rcon: [Byte] = [
		0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
		0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
		0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91,
	]
	let key_size: Int
	let block_size: Int

	public init(mod: Int, keySize: Int, blockSize: Int) throws {
		self.key_size = keySize
		self.block_size = blockSize
		self.sBox = try SBox(mod: mod)
	}

	public func expandKey(key: Symmetric.Block) async throws -> [Symmetric.Block] {
		let nk = key_size / 4
		let nb = block_size / 4

		let rounds =
			switch key_size {
				case 16: 10
				case 24: 12
				case 32: 14
				default: 0
			}

		let totalWords = nb * (rounds + 1)
		var w = Array(repeating: Word(0), count: totalWords)
        for i in 0..<nk {
            w[i] = Word(key[4*i]) << 24 |
                   Word(key[4*i + 1]) << 16 |
                   Word(key[4*i + 2]) << 8 |
                   Word(key[4*i + 3])
        }

        for i in nk..<totalWords {
            var temp = w[i-1]
            
            if i % nk == 0 {
                temp = await subWord(rotWord(temp)) ^ (Word(Self.rcon[i/nk]) << 24)
            } else if nk > 6 && i % nk == 4 {
                temp = await subWord(temp)
            }
            
            w[i] = w[i-nk] ^ temp
        }
        return []
	}
	private func subWord(_ word: Word) async -> Word {
        var result: Word = 0
        for i in 0..<4 {
            let byte = Byte((word >> (24 - 8*i)) & 0xFF)
            let subByte = await sBox.SBox[Int(byte)]
            result |= Word(subByte) << (24 - 8*i)
        }
        return result
	}
	private func rotWord(_ word: Word) -> Word {
        return (word << 8) | (word >> 24)
	}
	private func FormatRoundKeys(expandedKey: Block, blockSizeBytes: Int, rounds: Int) -> [Block] {
		var roundKeys: [Block] = []
		for i in 0...rounds {
			roundKeys.append(Array(expandedKey[i * blockSizeBytes..<(i + 1) * blockSizeBytes]))
		}
		return roundKeys
	}
}
