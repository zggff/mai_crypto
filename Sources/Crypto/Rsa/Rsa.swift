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
		let p: BigInt
		let q: BigInt
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
					Rsa.KeyGenerator.randomBigInt(
						bitLength: primeBitLength, rand: &randomGen) | 1
				if isProbablePrime(candidate) {
					return candidate
				}
			}
		}

		public func isProbablePrime(_ n: BigInt) -> Bool {
			let generator: (Int) -> BigInt = { bits in
				var rng = SystemRandomNumberGenerator()
				return KeyGenerator.randomBigInt(bitLength: bits, rand: &rng)
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
					pri: PrivateKey(d: d, p: p, q: q))
			}
		}

		static func randomBigInt(bitLength: Int, rand: inout SystemRandomNumberGenerator) -> BigInt
		{
			precondition(bitLength >= 2)
			let bytes = (bitLength + 7) / 8
			var data = Data(count: bytes)
			data.withUnsafeMutableBytes { (ptr: UnsafeMutableRawBufferPointer) in
				let buf = ptr.bindMemory(to: UInt8.self)
				for i in 0..<bytes {
					buf[i] = UInt8.random(in: 0...255, using: &rand)
				}
			}
			var value = BigInt(Data(data))
			let topBit = BigInt(1) << (bitLength - 1)
			value |= topBit
			return value
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

	func encrypt(message: BigInt, key: PublicKey) -> BigInt {
		return RsaMath.modPow(message, key.e, key.n)
	}

	func decrypt(cipher: BigInt) throws -> BigInt {
		guard let kp = keyPair else {
			throw EncryptionError.keyNotSet
		}
		return RsaMath.modPow(cipher, kp.pri.d, kp.pub.n)
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
