import Darwin

public enum BitOrder {
	case forward
	case backward
}

public enum FirstBitIndex {
	case zero
	case one
}

// only direct p-block rule is a map where
public func transpose(data: [Byte], rule: [Int], order: BitOrder, firstBit: FirstBitIndex)
	-> [Byte]?
{
	let shift =
		switch firstBit {
			case .one: 1
			default: 0
		}

	if data.count * 8 % rule.count != 0 {
		return nil
	}
	var b = Array.init(repeating: UInt8(0), count: data.count)
	for i in 0..<data.count * 8 {
		let block = i / rule.count
		let blockShift = rule[i % rule.count] - shift
		let pos =
			switch order {
				case .forward: block * rule.count + blockShift
				case .backward: (block + 1) * rule.count - blockShift - 1
			}
		b.setBit(pos, data.bit(i))
	}
	return b
}

public protocol KeyExpander {
	func expandKey(key: [Byte]) -> [[Byte]]
}

public protocol EncryptTransposer {
	func transpose(data: [Byte], key: [Byte]) -> [Byte]
}

public protocol Encryptor {
	mutating func setKey(key: [Byte])
	func encrypt(data: [Byte]) async throws -> [Byte]
	func decrypt(data: [Byte]) async throws -> [Byte]
}

public enum EncryptionMode: CaseIterable & Sendable {
	case ecb
	case cbc
	case pcbc
	case cfb
	case ofb
	case ctr
	case randomDelta
}

public enum PaddingMode: CaseIterable & Sendable {
	case zeros
	case ansiX923
	case pkcs7
	case iso10126
}

public enum EncryptionModeArg: Sendable {}

extension Array {
	public var lastMut: Element {
		get {
			return self[count - 1]
		}
		set {
			self[count - 1] = newValue
		}
	}
}

public typealias Block = [Byte]

extension Array {
	public func splitInSubArrays(into size: Int) -> [[Element]] {
		let cnt = (self.count - 1) / size + 1
		return (0..<cnt).map({ i in Array(self[i * size..<Swift.min(((i + 1) * size), self.count)])
		})
	}
}

public enum EncryptionError: Error {
	case empty
	case notFitting
	case runtimeError(String)
}

public class SymmetricEncryptor: Encryptor {
	var key: [Byte]
	let mode: EncryptionMode
	let padding: PaddingMode
	let iv: [Byte]?
	let args: [EncryptionModeArg]

	public init?(
		key: [Byte], mode: EncryptionMode, padding: PaddingMode, iv: [Byte]?,
		args: [EncryptionModeArg]
	) {
		if key.count > 256 {
			return nil
		}
		if padding == PaddingMode.ansiX923 && key.count > 8 {
			return nil
		}

		if let iv = iv {
			if iv.count != key.count {
				return nil
			}
		}

		self.key = key
		self.mode = mode
		self.padding = padding
		self.iv = iv
		self.args = args
	}

	public func setKey(key: [Byte]) {
		self.key = key
	}

	func padData(data: [Byte]) -> [Block] {
		var blocks = data.splitInSubArrays(into: key.count)
		let to_pad =
			blocks.last!.count % key.count == 0 ? 0 : key.count - (blocks.last!.count % key.count)
		// because ansiX923 always adds between 1 to 8 bytes
		if padding != PaddingMode.ansiX923 && to_pad == 0 {
			return blocks
		}
		switch padding {
			case .zeros:
				blocks[blocks.count - 1].append(contentsOf: Array(repeating: 0, count: to_pad))
			case .pkcs7:
				blocks[blocks.count - 1].append(
					contentsOf: Array(repeating: UInt8(to_pad), count: to_pad))
			case .iso10126:
				blocks[blocks.count - 1].append(
					contentsOf: (1..<to_pad).map({ _ in UInt8.random(in: 0...255) }))
				blocks[blocks.count - 1].append(UInt8(to_pad))
			case .ansiX923:
				let to_pad = to_pad == 0 ? 8 : to_pad
				if to_pad == 8 {
					blocks.append([])
				}
				blocks[blocks.count - 1].append(
					contentsOf: (1..<to_pad).map({ _ in UInt8.random(in: 0...255) }))
				blocks[blocks.count - 1].append(UInt8(to_pad))
		}
		return blocks
	}

	func unpadData(data: inout [Byte]) throws {
		switch self.padding {
			case .zeros:
				for i in (1...key.count) {
					if data[data.count - i] != 0 {
						data.removeLast(i - 1)
						break
					}
				}
			case .pkcs7:
				let n = data[data.count - 1]
				guard n < key.count && n < data.count else {
					return
				}

				let slice = data[data.count - Int(n)..<data.count]
				if slice.map({ $0 == n }).reduce(true, { x, y in x && y }) {
					data.removeLast(Int(n))
				}
			case .iso10126:
				let n = data[data.count - 1]
				guard n < key.count && n < data.count else {
					return
				}
				data.removeLast(Int(n))
			case .ansiX923:
				let n = data[data.count - 1]
				guard n <= key.count && n >= 1 && n < data.count else {
					throw EncryptionError.runtimeError(
						"\(n) - invalid ending for ansiX9.23 padding, value must be between 1 and 8"
					)
				}
				data.removeLast(Int(n))
		}

	}

	// TODO: Do more with encrypt and decrypt
	static func encryptBlock(block: inout Block, key: Block) {
		block ^= key
	}
	static func decryptBlock(block: inout Block, key: Block) {
		block ^= key
	}

	public func encrypt(data: [Byte]) async throws -> [Byte] {
		if data.isEmpty {
			throw EncryptionError.empty
		}
		let padded = padData(data: data)
		let key = self.key
		let res: [Byte]
		switch mode {
			case .ecb:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for block in padded {
					tasks.append(
						Task {
							var new_block = block
							SymmetricEncryptor.encryptBlock(
								block: &new_block, key: key)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
			case .cbc:
				var blocks = [self.iv ?? Array(repeating: 0, count: key.count)]
				for block in padded {
					blocks.append(block ^ blocks.last!)
					SymmetricEncryptor.encryptBlock(block: &blocks[blocks.count - 1], key: key)
				}
				res = blocks[1...].reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .pcbc:
				var to_xor = self.iv ?? Array(repeating: 0, count: key.count)
				var blocks: [Block] = []
				for block in padded {
					blocks.append(block ^ to_xor)
					SymmetricEncryptor.encryptBlock(block: &blocks[blocks.count - 1], key: key)
					to_xor ^= to_xor
					to_xor ^= block
					to_xor ^= blocks[blocks.count - 1]
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			default:
				throw EncryptionError.runtimeError("encryption mode \(mode) not implemented")
		}
		return res
	}

	public func decrypt(data: [Byte]) async throws -> [Byte] {
		if data.isEmpty {
			throw EncryptionError.empty
		}
		if data.count % key.count != 0 {
			throw EncryptionError.notFitting
		}

		let padded = data.splitInSubArrays(into: key.count)
		let key = self.key
		var res: [Byte]
		switch mode {
			case .ecb:
				var tasks: [Task<Block, Error>] = []
				var arr: [Byte] = []
				for block in padded {
					tasks.append(
						Task {
							var new_block = block
							SymmetricEncryptor.decryptBlock(
								block: &new_block, key: key)
							return new_block
						})
				}
				for task in tasks {
					arr.append(contentsOf: try await task.value)
				}
				res = arr
			case .cbc:
				var blocks: [Block] = []
				var prev_block = self.iv ?? Array(repeating: 0, count: key.count)
				for block in padded {
					blocks.append(block)
					SymmetricEncryptor.decryptBlock(block: &blocks[blocks.count - 1], key: key)
					blocks[blocks.count - 1] ^= prev_block
					prev_block = block
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})
			case .pcbc:
				var to_xor = self.iv ?? Array(repeating: 0, count: key.count)
				var blocks: [Block] = []
				for block in padded {
					blocks.append(block)
					SymmetricEncryptor.decryptBlock(block: &blocks.lastMut, key: key)
					blocks.lastMut ^= to_xor
					to_xor ^= to_xor
					to_xor ^= block
					to_xor ^= blocks.lastMut
				}
				res = blocks.reduce(
					[],
					{ partial, block in
						return partial + block
					})

			default:
				throw EncryptionError.runtimeError("decryption mode \(mode) not implemented")
		}
		try unpadData(data: &res)
		return res
	}
}
