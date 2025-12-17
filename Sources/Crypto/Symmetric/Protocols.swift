public typealias Word = UInt32
public typealias Byte = UInt8
public typealias Block = [Byte]


public enum BitOrder {
	case forward
	case backward
}

public enum FirstBitIndex {
	case zero
	case one
}

public protocol KeyExpander: Sendable {
	func expandKey(key: Block) async throws -> [Block]
	func keySizes() -> [Int]?
}

public protocol EncryptTransposer: Sendable {
	func transpose(data: Block, key: Block) async throws -> Block
	func preProcess(data: Block, encrypt: Bool) throws -> Block
	func postProcess(data: Block, encrypt: Bool) throws -> Block
	func blockSize() -> Int?
}

extension EncryptTransposer {
	public func preProcess(data: Block, encrypt: Bool = true) throws -> Block { return data }
	public func postProcess(data: Block, encrypt: Bool = true) throws -> Block { return data }
}

public protocol Encryptor: Sendable {
	func setKey(key: Block) async throws
	func encrypt(data: Block) async throws -> Block
	func decrypt(data: Block) async throws -> Block
	func blockSize() async -> Int?
	func keySizes() async -> [Int]?
}



public enum EncryptionModeArg: Sendable {}


public enum EncryptionError: Error {
	case notFitting
	case runtimeError(String)
	case blockSize(Int, String?)
	case keySize(Int, String?)
	case invalidPadding
	case outOfRange(Int, Int)
	case keyNotSet
	case iv
	case fileOpen(String)
}

