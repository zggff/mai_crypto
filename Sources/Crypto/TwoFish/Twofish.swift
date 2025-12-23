import Foundation

public struct TwofishEncryptor: Encryptor {
	struct Constants {
		let G_M: Word = 0x0169
		let G_MOD: Word = 0x0000_014d

		let qt0: InlineArray<2, InlineArray<16, Byte>> = [
			[8, 1, 7, 13, 6, 15, 3, 2, 0, 11, 5, 9, 14, 12, 10, 4],
			[2, 8, 11, 13, 15, 7, 6, 14, 3, 1, 9, 4, 0, 10, 12, 5],
		]
		let qt1: InlineArray<2, InlineArray<16, Byte>> = [
			[14, 12, 11, 8, 1, 2, 3, 5, 15, 4, 10, 6, 7, 0, 9, 13],
			[1, 14, 2, 11, 4, 12, 3, 7, 6, 13, 10, 5, 15, 9, 0, 8],
		]
		let qt2: InlineArray<2, InlineArray<16, Byte>> = [
			[11, 10, 5, 14, 6, 13, 9, 0, 12, 8, 15, 3, 2, 4, 7, 1],
			[4, 12, 7, 5, 1, 6, 9, 10, 0, 14, 13, 8, 2, 11, 3, 15],
		]
		let qt3: InlineArray<2, InlineArray<16, Byte>> = [
			[13, 7, 15, 4, 1, 2, 6, 14, 9, 11, 3, 0, 8, 5, 12, 10],
			[11, 9, 5, 1, 12, 3, 13, 14, 6, 4, 7, 15, 2, 0, 8, 10],
		]
		let ror4: InlineArray<16, Byte> = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
		let ashx: InlineArray<16, Byte> = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]
	}

	let const = Constants()
	var l_key: InlineArray<40, Word>
	var s_key: InlineArray<4, Word>
	var k_len: Int
	var key_set: Bool

	private init(
		l_key: InlineArray<40, Word>, s_key: InlineArray<4, Word>, k_len: Int, key_set: Bool
	) {
		self.l_key = l_key
		self.s_key = s_key
		self.k_len = k_len
		self.key_set = key_set
	}
	public func clone() -> Self {
		return Self(l_key: l_key, s_key: s_key, k_len: k_len, key_set: key_set)
	}

	public init() {
		l_key = InlineArray(repeating: 0)
		s_key = InlineArray(repeating: 0)
		k_len = 0
		key_set = false

	}
	private func make_uint32(_ a: Byte, _ b: Byte, _ c: Byte, _ d: Byte) -> Word {
		return Word(a) | Word(b) << 8 | Word(c) << 16 | Word(d) << 24

	}
	private func words_to_bytes(words: [Word]) -> [Byte] {
		var res = Array(repeating: Byte(0), count: 16)
		for i in 0..<4 {
			res[i * 4] = byte(words[i], 0)
			res[i * 4 + 1] = byte(words[i], 1)
			res[i * 4 + 2] = byte(words[i], 2)
			res[i * 4 + 3] = byte(words[i], 3)
		}
		return res
	}
	private func bytes_to_words(bytes: [Byte]) -> [Word] {
		var res = Array(repeating: Word(0), count: 4)
		for i in 0..<4 {
			res[i] = make_uint32(
				bytes[i * 4],
				bytes[i * 4 + 1],
				bytes[i * 4 + 2],
				bytes[i * 4 + 3],
			)
		}
		return res
	}

	public mutating func setKey(key: Block) async throws {
		guard keySizes()!.contains(key.count) else {
			throw EncryptionError.keySize(key.count, nil)
		}
		var key_words = Array(repeating: UInt32(0), count: key.count / 4)
		for i in 0..<key_words.count {
			let word = make_uint32(
				key[i * 4],
				key[i * 4 + 1],
				key[i * 4 + 2],
				key[i * 4 + 3]
			)
			key_words[i] = word
		}
		initialize(key_words: key_words)
		key_set = true
	}

	private func mds_rem(_ p0: Word, _ p1: Word) -> Word {
		var p1 = p1
		var p0 = p0
		for _ in 0..<8 {
			let t = p1 >> 24
			p1 = (p1 << 8) | (p0 >> 24)
			p0 <<= 8  // Shift others up
			var u = (t << 1)
			if t & 0x80 != 0 {
				// Subtract modular polynomial on overflow
				u ^= Constants().G_MOD
			}
			p1 ^= t ^ (u << 16)  // Remove t * (a * x^2 + 1)
			u ^= (t >> 1)  // Form u = a * t + t / a = t * (a + 1 / a);
			if t & 0x01 != 0 {
				// Add the modular polynomial on underflow
				u ^= Constants().G_MOD >> 1
			}
			p1 ^= (u << 24) | (u << 8)  // Remove t * (a + 1/a) * (x^3 + x)
		}
		return p1
	}

	private func byte(_ x: Word, _ n: Int) -> Byte {
		return Byte((x >> (8 * n)) & 0xff)
	}
	private func q(_ n: Int, _ x: Byte) -> Byte {
		var a0 = Byte(0)
		var a1 = Byte(0)
		var a2 = Byte(0)
		var a3 = Byte(0)
		var a4 = Byte(0)
		var b0 = Byte(0)
		var b1 = Byte(0)
		var b2 = Byte(0)
		var b3 = Byte(0)
		var b4 = Byte(0)
		a0 = x >> 4
		b0 = x & 15
		a1 = a0 ^ b0
		b1 = const.ror4[Int(b0)] ^ const.ashx[Int(a0)]
		a2 = const.qt0[n][Int(a1)]
		b2 = const.qt1[n][Int(b1)]
		a3 = a2 ^ b2
		b3 = const.ror4[Int(b2)] ^ const.ashx[Int(a2)]
		a4 = const.qt2[n][Int(a3)]
		b4 = const.qt3[n][Int(b3)]
		return (b4 << 4) | a4
	}

	private func h_fun(_ x: Word, _ key: InlineArray<4, Word>) -> Word {
		var b0 = byte(x, 0)
		var b1 = byte(x, 1)
		var b2 = byte(x, 2)
		var b3 = byte(x, 3)
		switch k_len {
			case 4:
				b0 = q(1, b0) ^ byte(key[3], 0)
				b1 = q(0, b1) ^ byte(key[3], 1)
				b2 = q(0, b2) ^ byte(key[3], 2)
				b3 = q(1, b3) ^ byte(key[3], 3)
			case 3:
				b0 = q(1, b0) ^ byte(key[2], 0)
				b1 = q(1, b1) ^ byte(key[2], 1)
				b2 = q(0, b2) ^ byte(key[2], 2)
				b3 = q(0, b3) ^ byte(key[2], 3)
			case 2:
				b0 = q(0, q(0, b0) ^ byte(key[1], 0)) ^ byte(key[0], 0)
				b1 = q(0, q(1, b1) ^ byte(key[1], 1)) ^ byte(key[0], 1)
				b2 = q(1, q(0, b2) ^ byte(key[1], 2)) ^ byte(key[0], 2)
				b3 = q(1, q(1, b3) ^ byte(key[1], 3)) ^ byte(key[0], 3)
			default: ()
		}
		b0 = q(1, b0)
		b1 = q(0, b1)
		b2 = q(1, b2)
		b3 = q(0, b3)

		let m5b_b0 = GF256.mul(b0, 0x5b, mod32: const.G_M)
		let m5b_b1 = GF256.mul(b1, 0x5b, mod32: const.G_M)
		let m5b_b2 = GF256.mul(b2, 0x5b, mod32: const.G_M)
		let m5b_b3 = GF256.mul(b3, 0x5b, mod32: const.G_M)
		let mef_b0 = GF256.mul(b0, 0xef, mod32: const.G_M)
		let mef_b1 = GF256.mul(b1, 0xef, mod32: const.G_M)
		let mef_b2 = GF256.mul(b2, 0xef, mod32: const.G_M)
		let mef_b3 = GF256.mul(b3, 0xef, mod32: const.G_M)

		b0 ^= mef_b1 ^ m5b_b2 ^ m5b_b3
		b3 ^= m5b_b0 ^ mef_b1 ^ mef_b2
		b2 ^= mef_b0 ^ m5b_b1 ^ mef_b3
		b1 ^= mef_b0 ^ mef_b2 ^ m5b_b3

		return Word(b0) | (Word(b3) << 8) | (Word(b2) << 16) | (Word(b1) << 24)

	}

	private mutating func initialize(key_words: [Word]) {
		s_key = InlineArray(repeating: 0)
		l_key = InlineArray(repeating: 0)
		k_len = key_words.count / 2

		var me_key: InlineArray<4, Word> = [0, 0, 0, 0]
		var mo_key: InlineArray<4, Word> = [0, 0, 0, 0]
		for i in 0..<k_len {
			let a = key_words[i * 2]
			let b = key_words[i * 2 + 1]
			me_key[i] = a
			mo_key[i] = b
			s_key[k_len - i - 1] = mds_rem(a, b)
		}
		for i in stride(from: 0, to: 40, by: 2) {
			var a: Word = Word(0x0101_0101 * i)
			var b: Word = a + 0x0101_0101
			a = h_fun(a, me_key)
			b = h_fun(b, mo_key).rotl(8)
			l_key[i] = a &+ b
			l_key[i + 1] = (a &+ 2 &* b).rotl(9)
		}
	}

	private func g1_fun(_ x: Word) -> Word {
		return h_fun(x.rotl(8), s_key)
	}

	private func g0_fun(_ x: Word) -> Word {
		return h_fun(x, s_key)
	}

	private func encrypt(words in_blk: [Word]) async throws -> [Word] {
		var blk = Array(repeating: Word(0), count: 4)
		blk[0] = in_blk[0] ^ l_key[0]
		blk[1] = in_blk[1] ^ l_key[1]
		blk[2] = in_blk[2] ^ l_key[2]
		blk[3] = in_blk[3] ^ l_key[3]
		for rnd in 0..<8 {
			var t1 = g1_fun(blk[1])
			var t0 = g0_fun(blk[0])
			blk[2] = (blk[2] ^ (t0 &+ t1 &+ l_key[4 * rnd + 8])).rotr(1)
			blk[3] = blk[3].rotl(1) ^ (t0 &+ 2 &* t1 &+ l_key[4 * rnd + 9])

			t1 = g1_fun(blk[3])
			t0 = g0_fun(blk[2])
			blk[0] = (blk[0] ^ (t0 &+ t1 &+ l_key[4 * rnd + 10])).rotr(1)
			blk[1] = blk[1].rotl(1) ^ (t0 &+ 2 &* t1 &+ l_key[4 * rnd + 11])
		}

		var out_blk = Array(repeating: Word(0), count: 4)
		out_blk[0] = blk[2] ^ l_key[4]
		out_blk[1] = blk[3] ^ l_key[5]
		out_blk[2] = blk[0] ^ l_key[6]
		out_blk[3] = blk[1] ^ l_key[7]
		return out_blk
	}

	private func decrypt(words in_blk: [Word]) async throws -> [Word] {
		var blk = Array(repeating: Word(0), count: 4)
		blk[0] = in_blk[0] ^ l_key[4]
		blk[1] = in_blk[1] ^ l_key[5]
		blk[2] = in_blk[2] ^ l_key[6]
		blk[3] = in_blk[3] ^ l_key[7]

		for rnd in (0..<8).reversed() {
			var t1 = g1_fun(blk[1])
			var t0 = g0_fun(blk[0])
			// blk[2] = rotl(blk[2], 1) ^ (t0 &+ t1 &+ l_key[4 * rnd + 10])
			blk[2] = blk[2].rotl(1) ^ (t0 &+ t1 &+ l_key[4 * rnd + 10])
			blk[3] = (blk[3] ^ (t0 &+ 2 &* t1 &+ l_key[4 * rnd + 11])).rotr(1)

			t1 = g1_fun(blk[3])
			t0 = g0_fun(blk[2])
			blk[0] = blk[0].rotl(1) ^ (t0 &+ t1 &+ l_key[4 * rnd + 8])
			blk[1] = (blk[1] ^ (t0 &+ 2 &* t1 &+ l_key[4 * rnd + 9])).rotr(1)
		}

		var out_blk = Array(repeating: Word(0), count: 4)
		out_blk[0] = blk[2] ^ l_key[0]
		out_blk[1] = blk[3] ^ l_key[1]
		out_blk[2] = blk[0] ^ l_key[2]
		out_blk[3] = blk[1] ^ l_key[3]
		return out_blk
	}

	public func encrypt(data: Block) async throws -> Block {
		guard key_set else {
			throw EncryptionError.keyNotSet
		}
		guard data.count == blockSize() else {
			throw EncryptionError.blockSize(16, nil)
		}
		let words = bytes_to_words(bytes: data)
		let encrypted = try await encrypt(words: words)
		return words_to_bytes(words: encrypted)
	}

	public func decrypt(data: Block) async throws -> Block {
		guard key_set else {
			throw EncryptionError.keyNotSet
		}

		guard data.count == blockSize() else {
			throw EncryptionError.blockSize(16, nil)
		}

		let words = bytes_to_words(bytes: data)
		let encrypted = try await decrypt(words: words)
		return words_to_bytes(words: encrypted)
	}

	public func blockSize()  -> Int? {
		return 16
	}

	public func keySizes()  -> [Int]? {
		return [16, 24, 32]
	}

}
