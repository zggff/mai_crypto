import Symmetric

typealias Word = UInt32

public enum AesError: Error {
	case AesReducible
	case Runtime(msg: String)
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

final class AesExpander {
	let sBox: SBox
	static let rcon: [Byte] = [
		0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
		0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A, 0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97,
		0x35, 0x6A, 0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91,
	]
	let key_size: Int
	let block_size: Int
	let rounds: Int

	init(mod: Int, keySize: Int, blockSize: Int, rounds: Int) throws {
		self.key_size = keySize
		self.block_size = blockSize
		self.sBox = try SBox(mod: mod)
		self.rounds = rounds
	}

	func expandKey(key: Symmetric.Block) async throws -> [Word] {
		let nk = key_size / 4
		let nb = block_size / 4

		let totalWords = nb * (rounds + 1)
		var w = Array(repeating: Word(0), count: totalWords)
		for i in 0..<nk {
			w[i] =
				Word(key[4 * i]) << 24 | Word(key[4 * i + 1]) << 16 | Word(key[4 * i + 2]) << 8
				| Word(key[4 * i + 3])
		}

		for i in nk..<totalWords {
			var temp = w[i - 1]

			if i % nk == 0 {
				temp = await subWord(rotWord(temp)) ^ (Word(Self.rcon[i / nk]) << 24)
			} else if nk > 6 && i % nk == 4 {
				temp = await subWord(temp)
			}

			w[i] = w[i - nk] ^ temp
		}

		return w
	}
	private func subWord(_ word: Word) async -> Word {
		var result: Word = 0
		for i in 0..<4 {
			let byte = Byte((word >> (24 - 8 * i)) & 0xFF)
			let subByte = await sBox.SBox[Int(byte)]
			result |= Word(subByte) << (24 - 8 * i)
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

public struct AesEncryptor: Encryptor {
	typealias State = [[Byte]]
	let block_size: Int
	let key_size: Int
	let sbox: SBox
	let expandedKey: [Word]
	let rounds: Int
	let nb: Int

    public func blockSize() -> Int? {
        return block_size
    }

	public init(key: Block, keySize: Int, blockSize: Int, irreducible: Int = 283) async throws {
		guard keySize == 16 || keySize == 24 || keySize == 32 else {
			throw EncryptionError.keySize(keySize, nil)
		}
		guard blockSize == 16 || blockSize == 24 || blockSize == 32 else {
			throw EncryptionError.blockSize(keySize, nil)
		}
		guard key.count == keySize else {
			throw EncryptionError.keySize(keySize, nil)
		}

		self.rounds = Self.numberOfRounds(keySize: keySize, blockSize: blockSize)
		let expander = try AesExpander(
			mod: irreducible, keySize: keySize, blockSize: blockSize, rounds: rounds)
		self.expandedKey = try await expander.expandKey(key: key)
		self.block_size = blockSize
		self.key_size = keySize
		self.sbox = try SBox(mod: irreducible)
		self.nb = blockSize / 4

	}
	public func encrypt(data: Symmetric.Block) async throws -> Symmetric.Block {
		var state = toStateMatrix(data)

		addRoundKey(&state, 0)
		for round in 1..<rounds {
			await subBytes(&state)
			shiftRows(&state)
			mixColumns(&state)
			addRoundKey(&state, round)
		}

		await subBytes(&state)
		shiftRows(&state)
		addRoundKey(&state, rounds)

		return fromStateMatrix(state)

	}

	public func decrypt(data: Symmetric.Block) async throws -> Symmetric.Block {
		var state = toStateMatrix(data)

		addRoundKey(&state, rounds)
		invShiftRows(&state)
		await invSubBytes(&state)

		for round in (1..<rounds).reversed() {
			addRoundKey(&state, round)
			invMixColumns(&state)
			invShiftRows(&state)
			await invSubBytes(&state)
		}

		addRoundKey(&state, 0)

		return fromStateMatrix(state)

	}

	private func toStateMatrix(_ block: Block) -> State {
		var state = Array(repeating: Array(repeating: Byte(0), count: nb), count: 4)
		for row in 0..<4 {
			for col in 0..<nb {
				state[row][col] = block[row + 4 * col]
			}
		}
		return state
	}

	private func fromStateMatrix(_ state: State) -> Block {
		var bytes = Block(repeating: 0, count: block_size)
		for row in 0..<4 {
			for col in 0..<nb {
				bytes[row + 4 * col] = state[row][col]
			}
		}
		return bytes
	}

	private static func numberOfRounds(keySize: Int, blockSize: Int) -> Int {
        if keySize == 16 && blockSize == 16 {
            return 10
        }
        if keySize == 32 && blockSize == 32 {
            return 14
        }
        return 12
	}

	private func addRoundKey(_ state: inout State, _ round: Int) {
		for col in 0..<nb {
			let word = expandedKey[round * nb + col]
			for row in 0..<4 {
				let keyByte = Byte((word >> (24 - 8 * row)) & 0xFF)
				state[row][col] ^= keyByte
			}
		}
	}

	private func subBytes(_ state: inout State) async {
		for r in 0..<4 {
			for c in 0..<nb {
				state[r][c] = await sbox.SBox[Int(state[r][c])]
			}
		}
	}

	private func invSubBytes(_ state: inout State) async {
		for r in 0..<4 {
			for c in 0..<nb {
				state[r][c] = await sbox.InvSBox[Int(state[r][c])]
			}
		}
	}

	private func shiftRows(_ state: inout State) {
		let temp1 = state[1][0]
		state[1][0] = state[1][1]
		state[1][1] = state[1][2]
		state[1][2] = state[1][3]
		state[1][3] = temp1

		let temp2a = state[2][0]
		let temp2b = state[2][1]
		state[2][0] = state[2][2]
		state[2][1] = state[2][3]
		state[2][2] = temp2a
		state[2][3] = temp2b

		let temp3 = state[3][3]
		state[3][3] = state[3][2]
		state[3][2] = state[3][1]
		state[3][1] = state[3][0]
		state[3][0] = temp3
	}

	private func invShiftRows(_ state: inout State) {
		let temp1 = state[1][3]
		state[1][3] = state[1][2]
		state[1][2] = state[1][1]
		state[1][1] = state[1][0]
		state[1][0] = temp1

		let temp2a = state[2][0]
		let temp2b = state[2][1]
		state[2][0] = state[2][2]
		state[2][1] = state[2][3]
		state[2][2] = temp2a
		state[2][3] = temp2b

		let temp3 = state[3][0]
		state[3][0] = state[3][1]
		state[3][1] = state[3][2]
		state[3][2] = state[3][3]
		state[3][3] = temp3

	}

	private func mixColumns(_ state: inout State) {
		var tempCol: [Byte] = [0, 0, 0, 0]

		for c in 0..<nb {
			for r in 0..<4 {
				tempCol[r] = state[r][c]
			}
			state[0][c] =
				(GF256.mul(tempCol[0], 2, mod: 0x1B) ^ GF256.mul(tempCol[1], 3, mod: 0x1B)
					^ tempCol[2] ^ tempCol[3])
			state[1][c] =
				(tempCol[0] ^ GF256.mul(tempCol[1], 2, mod: 0x1B)
					^ GF256.mul(tempCol[2], 3, mod: 0x1B) ^ tempCol[3])
			state[2][c] =
				(tempCol[0] ^ tempCol[1] ^ GF256.mul(tempCol[2], 2, mod: 0x1B)
					^ GF256.mul(tempCol[3], 3, mod: 0x1B))
			state[3][c] =
				(GF256.mul(tempCol[0], 3, mod: 0x1B) ^ tempCol[1] ^ tempCol[2]
					^ GF256.mul(tempCol[3], 2, mod: 0x1B))
		}
	}

	private func invMixColumns(_ state: inout State) {
		let nb = block_size / 4
		var tempCol: [Byte] = [0, 0, 0, 0]

		for c in 0..<nb {
			for r in 0..<4 {
				tempCol[r] = state[r][c]
			}

			state[0][c] =
				(GF256.mul(tempCol[0], 0x0E, mod: 0x1B) ^ GF256.mul(tempCol[1], 0x0B, mod: 0x1B)
					^ GF256.mul(tempCol[2], 0x0D, mod: 0x1B)
					^ GF256.mul(tempCol[3], 0x09, mod: 0x1B))
			state[1][c] =
				(GF256.mul(tempCol[0], 0x09, mod: 0x1B) ^ GF256.mul(tempCol[1], 0x0E, mod: 0x1B)
					^ GF256.mul(tempCol[2], 0x0B, mod: 0x1B)
					^ GF256.mul(tempCol[3], 0x0D, mod: 0x1B))
			state[2][c] =
				(GF256.mul(tempCol[0], 0x0D, mod: 0x1B) ^ GF256.mul(tempCol[1], 0x09, mod: 0x1B)
					^ GF256.mul(tempCol[2], 0x0E, mod: 0x1B)
					^ GF256.mul(tempCol[3], 0x0B, mod: 0x1B))
			state[3][c] =
				(GF256.mul(tempCol[0], 0x0B, mod: 0x1B) ^ GF256.mul(tempCol[1], 0x0D, mod: 0x1B)
					^ GF256.mul(tempCol[2], 0x09, mod: 0x1B)
					^ GF256.mul(tempCol[3], 0x0E, mod: 0x1B))
		}
	}
}
