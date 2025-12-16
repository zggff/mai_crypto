struct GF256 {
	enum GF256Error: Error {
		case zeroDivision
	}
	public static func add(_ a: Byte, _ b: Byte) -> Byte {
		return a ^ b
	}
	public static func mul(_ a: Byte, _ b: Byte, mod: Byte) -> Byte {
		var result: Byte = 0
		var a = a
		var b = b
		while b > 0 {
			if (b & 1) == 1 {
				result ^= a
			}

			let hi_bit_set = a & 0x80
			a <<= 1
			if hi_bit_set != 0 {
				a ^= mod
			}
			b >>= 1
		}
		return result
	}
	public static func pow(_ a: Byte, e: Byte, mod: Byte) -> Byte {
		var result: Byte = 1
		var a = a
		var e = e
		while e > 0 {
			if (e & 1) == 1 {
				result = mul(result, a, mod: mod)
			}
			a = mul(a, a, mod: mod)
			e >>= 1
		}
		return result
	}
	public static func inv(_ a: Byte, mod: Byte) -> Byte {
		return a == 0 ? 0 : pow(a, e: 254, mod: mod)
	}

	private static func remainder(of: Int, by: Int) throws -> Int {
		if by == 0 {
			throw GF256Error.zeroDivision
		}
		var of = of
		let by_degree = degree(by)
		while degree(of) >= by_degree {
			of ^= by << (degree(of) - by_degree)
		}
		return of
	}

	private static func degree(_ a: Int) -> Int {
		for i in (0...31).reversed() {
			if ((a >> i) & 1) == 1 {
				return i
			}
		}
		return -1
	}

	public static func irreducible(_ a: Byte) -> Bool {
		return irreducible(Int(a) | (1 << 8))
	}

	public static func irreducible(_ a: Int) -> Bool {
		if a == 0 {
			return false
		}
		if (a & 1) == 0 { return false }
		let irreducibleFactors = [
			0b11,  // x+1
			0b111,  // x^2+x+1
			0b1011,  // x^3+x+1
			0b1101,  // x^3+x^2+1
			0b10011,  // x^4+x+1
			0b11001,  // x^4+x^3+1
			0b11111,  // x^4+x^3+x^2+x+1
		]
		for factor in irreducibleFactors {
			let remainder = try! remainder(of: a, by: factor)
			if remainder == 0 {
				return false
			}
		}
		return true
	}

	public static func allIrreducible() -> [Int] {
		var res: [Int] = []
		for i in 0..<256 {
			let p = i | (1 << 8)
			if irreducible(p) {
				res.append(p)
			}
		}
		return res
	}

	private static func binaryPolynomialGCD(_ a: Int, _ b: Int) -> Int {
		var x = a
		var y = b

		while y != 0 {
			let degX = degree(x)
			let degY = degree(y)
			if degX >= degY {
				let shift = degX - degY
				x ^= (y << shift)
			} else {
				swap(&x, &y)
			}
		}
		return x
	}

    public static func factor8Polynomial(_ polynomial: Byte) -> [Int: Int] {
        return factorPolynomial(Int(polynomial) | (1 << 8))

    }


	public static func factorPolynomial(_ polynomial: Int) -> [Int: Int] {
		let n = degree(polynomial)

		var factors: [Int: Int] = [:]
		for i in 2..<(1 << min(n, 8)) {
			let testPoly = i

			let gcd = binaryPolynomialGCD(polynomial, testPoly)
			if gcd > 1 && gcd != polynomial {
				factors[gcd] = (factors[gcd] ?? 0) + 1
			}
		}

		if factors.isEmpty {
			factors[polynomial] = 1
		}

		return factors
	}

}
