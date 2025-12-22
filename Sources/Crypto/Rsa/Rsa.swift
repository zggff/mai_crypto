import BigInt
import Foundation

public class Rsa {
	public enum TestType: Sendable {
		case fermat
		case solovayStrassen
		case millerRabin
	}

	public struct PublicKey: Sendable {
		let n: BigInt
		let e: BigInt
	}

	public struct PrivateKey: Sendable {
		let d: BigInt
		let n: BigInt
        let q: BigInt
        let p: BigInt
	}

	public struct KeyPair: Sendable {
		let pub: PublicKey
		let pri: PrivateKey
	}

	public class KeyGenerator {
		let testType: TestType
		let minProbability: Double
		let primeBitLength: Int
		let math = RsaMath.self

		init(testType: TestType, minProbability: Double, primeBitLength: Int) {
			precondition(minProbability >= 0.5 && minProbability < 1.0)
			self.testType = testType
			self.minProbability = minProbability
			self.primeBitLength = primeBitLength
		}

		public func generateProbablePrime(randomGen: inout SystemRandomNumberGenerator) -> BigInt {
			while true {
				let candidate =
					AbstractPrimeTest.randomBigInt(
						bitLength: primeBitLength, rand: &randomGen) | 1
				if isProbablePrime(candidate) {
					return candidate
				}
			}
		}

		public func isProbablePrime(_ n: BigInt) -> Bool {
			let generator: (Int) -> BigInt = { bits in
				var rng = SystemRandomNumberGenerator()
				return AbstractPrimeTest.randomBigInt(bitLength: bits, rand: &rng)
			}
			switch testType {
				case .fermat:
					return FermatTest(minProbability: minProbability).isProbablyPrime(
						n, randomBitGenerator: generator)
				case .solovayStrassen:
					return SolovayStrassenTest(minProbability: minProbability).isProbablyPrime(
						n, randomBitGenerator: generator)
				case .millerRabin:
					return MillerRabinTest(minProbability: minProbability).isProbablyPrime(
						n, randomBitGenerator: generator)
			}
		}

		public func generateKeyPair() -> KeyPair {
			var rng = SystemRandomNumberGenerator()
			return generateKeyPair(randomGen: &rng)
		}

		public func generateKeyPair(randomGen: inout SystemRandomNumberGenerator) -> KeyPair {
			while true {
				let p = generateProbablePrime(randomGen: &randomGen)
				var q: BigInt
				repeat {
					q = generateProbablePrime(randomGen: &randomGen)
				} while q == p

				// prevent Fermat factorization: ensure |p - q| not too small
				let diff = (p > q) ? (p - q) : (q - p)
				let threshold = BigInt(1) << max(1, (primeBitLength / 2) - 16)
				if diff < threshold {
					continue
				}

				let n = p * q
				let phi = (p - 1) * (q - 1)

				var e: BigInt = 3
				e = BigInt(257)
				while math.gcd(e, phi) != 1 {
					e += 2
				}

				guard let d = math.modInverse(e, phi) else { continue }

				let nDouble = n
				let nBitWidth = nDouble.bitWidth
				let dMin = BigInt(1) << max(1, nBitWidth / 4)
				if d <= dMin {
					continue
				}

				return KeyPair(
					pub: PublicKey(n: n, e: e),
					pri: PrivateKey(d: d, n: n, q: q, p: p))
			}
		}


	}

	public var keyPair: KeyPair?

	init() {}

	func setKeyPair(_ kp: KeyPair) {
		self.keyPair = kp
	}

	func encrypt(message: BigInt) throws -> BigInt {
		guard let kp = keyPair else {
			throw EncryptionError.keyNotSet
		}
		return RsaMath.modPow(message, kp.pub.e, kp.pub.n)
	}

	static func encrypt(message: BigInt, key: PublicKey) -> BigInt {
		return RsaMath.modPow(message, key.e, key.n)
	}

	func decrypt(cipher: BigInt) throws -> BigInt {
		guard let kp = keyPair else {
			throw EncryptionError.keyNotSet
		}
		return RsaMath.modPow(cipher, kp.pri.d, kp.pri.n)
	}

    static func decrypt(cipher: BigInt, key: PrivateKey) -> BigInt {
		return RsaMath.modPow(cipher, key.d, key.n)
	}

	static func messageToBigInt(_ message: String) -> BigInt {
		let data = message.data(using: .utf8)!
		return BigInt(BigUInt(data))
	}

	static func bigIntToMessage(_ m: BigInt) -> String? {
		guard m >= 0 else { return nil }
		let bigUInt = BigUInt(m.magnitude)
		let data = bigUInt.serialize()
		return String(data: data, encoding: .utf8)
	}
}
