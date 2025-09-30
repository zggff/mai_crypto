public extension UInt8 {
	func bitStr() -> String {
		var res = "0b"
		for i in (0...7).reversed() {
			res += String(self[i] as UInt8)
		}
		return res
	}
	subscript(i: Int) -> Bool {
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
	subscript(at: Int) -> UInt8 {
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
}

public extension [UInt8] {

	func bit(_ at: Int) -> Bool {
		return self[at / 8] & (1 << (at % 8)) != 0
	}

	mutating func setBit(_ at: Int, _ val: Bool) {
		switch val {
		case false: self[at / 8] &= ~(1 << (at % 8))
		case true: self[at / 8] |= (1 << (at % 8))
		}
	}

}

