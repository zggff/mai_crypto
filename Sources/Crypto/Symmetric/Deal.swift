public final class DealTransposer: EncryptTransposer {
	public init() {}
	public func blockSize() -> Int? { return 16 }

	public func transpose(data: Block, key: Block) async throws -> Block {
		var des = try Feistel(expander: DesExpander(), transposer: DesTransposer())
		try await des.setKey(key: key)
		return try await des.encrypt(data: data)
	}
	public func preProcess(data: Block, encrypt: Bool = true) throws -> Block {
		if encrypt {
			return data
		}
		let middle = data.count / 2
		let left = Array(data[..<middle])
		let right = Array(data[middle...])
		return right + left
	}
	public func postProcess(data: Block, encrypt: Bool = true) throws -> Block {
		guard encrypt else {
			return data
		}
		let middle = data.count / 2
		let left = Array(data[..<middle])
		let right = Array(data[middle...])
		return right + left
	}
}

public final class DealExpander: KeyExpander {
	public static let DealKeyInit: Block = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]
	public func keySizes() -> [Int]? {
		return [16, 24, 32]
	}
	public init() {}
	public func expandKey(key: Block) async throws -> [Block] {
		guard key.count == 16 || key.count == 24 || key.count == 32 else {
			throw EncryptionError.keySize(key.count, "Deal key must be 8 or 16 or 32 bytes")
		}
		var keys_des: [Block] = []
		for i in 0..<key.count / 8 {
			keys_des.append(Array(key[i * 8..<(i + 1) * 8]))
		}
		let rounds =
			switch key.count {
				case 32: 8
				default: 6
			}
		var des = try Feistel(expander: DesExpander(), transposer: DesTransposer())
		try await des.setKey(key: Self.DealKeyInit)
		var keys: [Block] = []
		await keys.append(try des.encrypt(data: keys_des[0]))
		for k in keys_des[1...] {
			await keys.append(try des.encrypt(data: k ^ keys.last!))
		}
		var const_shift = 1
		for i in keys_des.count..<rounds {
			var single_bit: Block = Array(repeating: 0, count: 8)
			single_bit.setBit(const_shift, true)
			const_shift *= 2
			await keys.append(
				try des.encrypt(
					data: keys_des[i % keys_des.count] ^ single_bit ^ keys.last!))
		}
		return keys
	}
}
