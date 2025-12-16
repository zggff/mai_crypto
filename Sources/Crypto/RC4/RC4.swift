import Foundation

public struct RC4 {
	private var S: [UInt8] = Array(0...255)
	private var i: Int = 0
	private var j: Int = 0
	private var key: [UInt8]?

	// TODO: Async ???
	public init() {
	}

	public mutating func setKey(key: Block) {
		self.key = key
		initializeState()
	}

	private mutating func initializeState() {
        self.S = Array(0...255)
		var j: Int = 0
		for i in 0...255 {
			j = (j + Int(S[i]) + Int(key![i % key!.count])) % 256
			S.swapAt(i, j)
		}
		self.i = 0
		self.j = 0
	}

	private mutating func nextByte() -> Byte {
		i = (i + 1) % 256
		j = (j + Int(S[i])) % 256
		S.swapAt(i, j)
		let t = (Int(S[i]) + Int(S[j])) % 256
		return S[t]
	}

	public mutating func reset() {
		guard self.key != nil else { return }
		initializeState()
	}

	public mutating func encrypt(data: Block) -> Block {
		var res = data
		encrypt(mutable: &res)
		return res
	}

	public mutating func encrypt(mutable: inout Block) {
		for k in 0..<mutable.count {
			mutable[k] ^= nextByte()
		}
	}

	public mutating func encrypt(in input: InputStream, out output: OutputStream) throws {
		guard key != nil else {
			throw EncryptionError.keyNotSet
		}
		input.open()
		output.open()
		defer {
			input.close()
			output.close()
		}
		let size = 1024 * 1024
		var buffer = Array(repeating: Byte(0), count: size)
		while true {
			let read = input.read(&buffer, maxLength: size)
			if read == 0 {
				break
			}
			encrypt(mutable: &buffer)
			output.write(buffer, maxLength: read)
		}
	}
}
