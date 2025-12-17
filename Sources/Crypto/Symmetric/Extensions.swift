import BigInt

extension Array {
	public var lastMut: Element {
		get {
			return self[count - 1]
		}
		set {
			self[count - 1] = newValue
		}
	}
	func chunked(into size: Int) -> [[Element]] {
		stride(from: 0, to: count, by: size).map {
			Array(self[$0..<Swift.min($0 + size, count)])
		}
	}

}

extension BinaryInteger {
	func rotl(_ by: Int) -> Self {
		return ((self << by) | (self >> (32 - by)))
	}
	func rotr(_ by: Int) -> Self {
		return ((self >> by) | (self << (32 - by)))
	}
}
