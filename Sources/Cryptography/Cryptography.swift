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

public enum EncryptionMode {
	case ecb
	case cbc
	case pcbc
	case cfb
	case ofb
	case ctr
	case randomDelta
}

public enum PaddingMode {
	case zeros
	case ansiX923
	case pkcs7
	case iso10126
}

public enum EncryptionModeArg {}

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
				blocks[blocks.count - 1].append(
					contentsOf: (1..<to_pad).map({ _ in UInt8.random(in: 0...255) }))
				blocks[blocks.count - 1].append(UInt8(to_pad))
		}
		return blocks
	}

	func unpadData(data: inout [Byte]) throws {
		switch self.padding {
			case .zeros:
				for i in (1...key.count).reversed() {
					if data[data.count - i] != 0 {
						data.removeLast(i - 1)
						break
					}
				}
			default:
				throw EncryptionError.runtimeError("unpadding for \(self.padding) not implemented")
		}

	}

	public func encrypt(data: [Byte]) async throws -> [Byte] {
		if data.isEmpty {
			throw EncryptionError.empty
		}
		let padded = padData(data: data)
		let key = self.key
		let res =
			switch mode {
				case .ecb:
					await withTaskGroup { group in
						for block in padded {
							group.addTask(operation: {
								var new_block = block
								for i in 0..<key.count {
									new_block[i] ^= key[i]
								}
								return new_block
							})
						}
						return await group.reduce(into: [Byte]()) { partial, block in
							partial.append(contentsOf: block)
						}
					}
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
		var res =
			switch mode {
				case .ecb:
					await withTaskGroup { group in
						for block in padded {
							group.addTask(operation: {
								var new_block = block
								for i in 0..<key.count {
									new_block[i] ^= key[i]
								}
								return new_block
							})
						}
						return await group.reduce(into: [Byte]()) { partial, block in
							partial.append(contentsOf: block)
						}
					}

				default:
					throw EncryptionError.runtimeError("decryption mode \(mode) not implemented")
			}
		try unpadData(data: &res)

		return res
	}
}
