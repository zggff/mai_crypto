public typealias Byte = UInt8

extension BinaryInteger {
	public func bitStr() -> String {
		var res = "0b"
		for i in (0...self.bitWidth).reversed() {
			res += String(self[i] as Self)
		}
		return res
	}
	public subscript(i: Int) -> Bool {
		get {
			return self & (1 << i) != 0
		}
		set(val) {
			switch val {
				case true: self |= (1 << i)
				case false: self &= ~(1 << i)
			}
		}
	}
	public subscript(at: Int) -> Self {
		get {
			return (self & (1 << at)) >> at
		}
		set(val) {
			switch val {
				case 0: self &= ~(1 << at)
				default: self |= (1 << at)
			}
		}
	}
	public func toArray() -> [UInt8] {
		guard self != 0 else {
			return [0]
		}
		var val = self
		var res: [UInt8] = []
		while val > 0 {
			res.append(UInt8(val & 0xff))
			val >>= 8
		}
		return res.reversed()
	}
	public func toArray(size: Int) -> [UInt8] {
		var val = self
		var res: [UInt8] = Array(repeating: 0, count: size)
        for i in (0..<size).reversed() {
			res[i] = (UInt8(val & 0xff))
			val >>= 8
		}
		return res
	}
}

extension [UInt8] {
	public func bit(_ at: Int) -> Bool {
		return self[at / 8] & (1 << (7 - (at % 8))) != 0
	}

	public mutating func setBit(_ at: Int, _ val: Bool) {
		switch val {
			case false: self[at / 8] &= ~(1 << (7 - (at % 8)))
			case true: self[at / 8] |= (1 << (7 - (at % 8)))
		}
	}

	public static func ^= (a: inout [UInt8], b: [UInt8]) {
		for i in 0..<a.count {
			a[i] ^= b[i]
		}
	}
	public static func += (a: inout [UInt8], b: [UInt8]) {
		for i in 0..<a.count {
			a[i] &+= b[i]
		}
	}
	public static func -= (a: inout [UInt8], b: [UInt8]) {
		for i in 0..<a.count {
			a[i] &-= b[i]
		}
	}
	public static func += (a: inout [UInt8], b: UInt64) {
		var remaining = b
		for i in (0..<a.count).reversed() {
			let res = remaining + UInt64(a[i])
			a[i] = UInt8(res % 256)
			remaining = res / 256
			if remaining == 0 {
				break
			}
		}
	}
	public static func += (a: inout [UInt8], b: Int) {
		a += UInt64(b)
	}

	public static func ^ (a: [UInt8], b: [UInt8]) -> [UInt8] {
		var res = a
		for i in 0..<res.count {
			res[i] ^= b[i]
		}
		return res
	}

	public static func random(size: Int) -> [UInt8] {
		var res = Array.init(repeating: 0, count: size)
		for i in 0..<size {
			res[i] = UInt8.random(in: 0...255)
		}
		return res
	}

	public func toUInt() -> UInt64 {
		return self.reduce(0) { soFar, byte in
			return soFar << 8 | UInt64(byte)
		}
	}
    public func toHexString(sep: String = "") -> String {
        var res = ""
        for val in self {
            if res.count > 0 {
                res += sep
            }
            var hex =  "\(String(val, radix: 16))"
            if hex.count < 2 {
                hex = "0"+hex
            }
            res += hex
        }
        return res
    }
    public func toBitString() -> String {
        var res = ""
        for val in self {
            let bits = String(val, radix: 2)
            var pad = ""
            for _ in 0..<(8 - bits.count) {
                pad += "0"
            }
            res += pad + bits + " "
        }
        return res
    }
}
