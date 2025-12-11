import BigInt
import Foundation

public struct RsaMath {
	public static func gcd(_ a: BigInt, _ b: BigInt) -> BigInt {
		var x = a.magnitude == 0 ? BigInt(0) : abs(a)
		var y = b.magnitude == 0 ? BigInt(0) : abs(b)
		while y != 0 {
			let r = x % y
			x = y
			y = r
		}
		return x
	}

	public static func extendedGCD(_ a: BigInt, _ b: BigInt) -> (g: BigInt, x: BigInt, y: BigInt) {
		var old_r = a
		var r = b
		var old_s = BigInt(1)
		var s = BigInt(0)
		var old_t = BigInt(0)
		var t = BigInt(1)

		while r != 0 {
			let q = old_r / r
			(old_r, r) = (r, old_r - q * r)
			(old_s, s) = (s, old_s - q * s)
			(old_t, t) = (t, old_t - q * t)
		}
		return (old_r, old_s, old_t)
	}

	public static func modInverse(_ a: BigInt, _ m: BigInt) -> BigInt? {
		let (g, x, _) = extendedGCD(a, m)
		if g != 1 && g != -1 { return nil }
		var inv = x % m
		if inv < 0 { inv += m }
		return inv
	}

	public static func modPow(_ base: BigInt, _ exponent: BigInt, _ modulus: BigInt) -> BigInt {
		precondition(modulus > 0, "modulus must be > 0")
		if modulus == 1 { return 0 }
		var result = BigInt(1)
		var b = base % modulus
		var e = exponent
		if e < 0 {
			guard let inv = modInverse(b, modulus) else {
				fatalError("base not invertible modulo modulus")
			}
			b = inv
			e = -e
		}
		while e > 0 {
			if (e & 1) == 1 {
				result = (result * b) % modulus
			}
			e >>= 1
			b = (b * b) % modulus
		}
		return result
	}

	public static func legendreSymbol(a: BigInt, p: BigInt) -> Int {
		precondition(p > 2 && p % 2 == 1, "p must be an odd prime")
		let aReduced = (a % p + p) % p
		if aReduced == 0 { return 0 }
		let pow = modPow(aReduced, (p - 1) / 2, p)
		if pow == 1 { return 1 }
		if pow == p - 1 { return -1 }
		return 0
	}

	public static func jacobiSymbol(a: BigInt, n: BigInt) -> Int {
		precondition(n > 0 && n % 2 == 1, "n must be positive odd")
		var aVar = (a % n + n) % n
		var nVar = n
		var result = 1
		while aVar != 0 {
			var e = 0
			while aVar % 2 == 0 {
				aVar >>= 1
				e += 1
			}
			if e % 2 == 1 {
				let nMod8 = Int(nVar % 8)
				if nMod8 == 3 || nMod8 == 5 {
					result = -result
				}
			}
			if aVar == 1 { return result }
			if (aVar % 4 == 3) && (nVar % 4 == 3) {
				result = -result
			}
			let temp = nVar % aVar
			nVar = aVar
			aVar = temp
		}
		return nVar == 1 ? result : 0
	}
}
