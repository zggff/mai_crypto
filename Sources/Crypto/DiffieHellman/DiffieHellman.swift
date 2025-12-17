import BigInt
import Foundation

public class DiffieHellman {
	public static let Primes: [BigInt] = {
		let limit = 1000
		var sieve = [Bool](repeating: true, count: limit + 1)
		sieve[0] = false
		sieve[1] = false
		for i in 2...limit {
			if sieve[i] {
				for j in stride(from: i * i, through: limit, by: i) {
					sieve[j] = false
				}
			}
		}
		return (2...limit).filter { sieve[$0] }.map { BigInt($0) }

	}()
	public struct Parameters: Sendable {
		public let p: BigInt  // Большое простое число
		public let g: BigInt  // Первообразный корень по модулю p
		public let bitLength: Int

		public init(p: BigInt, g: BigInt, bitLength: Int) {
			self.p = p
			self.g = g
			self.bitLength = bitLength
		}

		public func validate() -> Bool {
			return p > 2 && g > 1 && g < p && RsaMath.gcd(g, p) == 1
		}
		public func generatePublicKey(privateKey: BigInt) -> BigInt {
			return RsaMath.modPow(g, privateKey, p)
		}
	}

	public struct KeyPair: Sendable {
		public let privateKey: BigInt
		public let publicKey: BigInt
		public let parameters: Parameters

		public init(privateKey: BigInt, publicKey: BigInt, parameters: Parameters) {
			self.privateKey = privateKey
			self.publicKey = publicKey
			self.parameters = parameters
		}
	}

	/// generate parameters for DiffieHellman exchange
	/// - Parameters:
	///   - bitLength: length of p
	///   - testType: primality test
	///   - minProbability: required probability of number being prime
	///
	/// - Returns: params
	/// this function should not be used as it's slow and unoptimized
	/// for secure exchange bitLength should be very high >= 1024
	/// this algorithm can efficiently calculate 32 and may be used for 64
	public static func generateParameters(
		bitLength: Int = 32,
		testType: Rsa.TestType = .millerRabin,
		minProbability: Double = 0.999
	) -> Parameters? {
		// (p-1)/2 также должно быть простым для лучшей безопасности
		let keyGenerator = Rsa.KeyGenerator(
			testType: testType,
			minProbability: minProbability,
			primeBitLength: bitLength
		)

		var rng = SystemRandomNumberGenerator()

		let p = keyGenerator.generateProbablePrime(randomGen: &rng)

		let g = findPrimitiveRoot(p: p)

		return Parameters(p: p, g: g, bitLength: bitLength)
	}

	private static func findPrimitiveRoot(p: BigInt) -> BigInt {
		// let candidates: [BigInt] = [2, 3, 5, 7, 11, 13]
		let candidates: [BigInt] = Primes

		for g in candidates where g < p {
			let test = RsaMath.modPow(g, p - 1, p)
			if test == 1 {
				var isPrimitive = true
				let factors = factorize(n: p - 1)

				for factor in factors {
					let exponent = (p - 1) / factor
					let test2 = RsaMath.modPow(g, exponent, p)
					if test2 == 1 {
						isPrimitive = false
						break
					}
				}

				if isPrimitive {
					return g
				}
			}
		}

		return 2
	}

	private static func factorize(n: BigInt) -> [BigInt] {
		// TODO: better factorize
		var nCopy = n
		var factors: [BigInt] = []
		var divisor: BigInt = 2

		while divisor * divisor <= nCopy {
			while nCopy % divisor == 0 {
				if !factors.contains(divisor) {
					factors.append(divisor)
				}
				nCopy /= divisor
			}
			divisor += 1
		}

		if nCopy > 1 && !factors.contains(nCopy) {
			factors.append(nCopy)
		}

		return factors
	}

	public static func generateKeyPair(parameters: Parameters) -> KeyPair {
		var rng = SystemRandomNumberGenerator()
		let privateKey = generateRandomPrivateKey(p: parameters.p, rng: &rng)
		let publicKey = RsaMath.modPow(parameters.g, privateKey, parameters.p)

		return KeyPair(
			privateKey: privateKey,
			publicKey: publicKey,
			parameters: parameters
		)
	}

	private static func generateRandomPrivateKey(p: BigInt, rng: inout SystemRandomNumberGenerator)
		-> BigInt
	{
		let bitLength = p.bitWidth
		var privateKey: BigInt

		repeat {
			privateKey = Rsa.KeyGenerator.randomBigInt(bitLength: bitLength, rand: &rng) % (p - 2)
		} while privateKey <= 1

		return privateKey
	}

	public static func computeSharedSecret(
		privateKey: BigInt,
		otherPublicKey: BigInt,
		p: BigInt
	) -> BigInt {
		return RsaMath.modPow(otherPublicKey, privateKey, p)
	}

	public static func deriveSymmetricKey(
		sharedSecret: BigInt,
		keySize: Int,
		salt: [Byte]? = nil,
		info: [Byte]? = nil
	) throws -> [Byte] {
		let ikm = sharedSecretToBytes(sharedSecret)

		let contextInfo =
			info ?? [
				0x44, 0x48, 0x2d, 0x4b, 0x44, 0x46,  // "DH-KDF" in ASCII
			]

		let hkdf = HKDF(hash: .sha256)
		return try hkdf.deriveKey(
			salt: salt,
			ikm: ikm,
			info: contextInfo,
			length: keySize
		)
	}
	private static func sharedSecretToBytes(_ sharedSecret: BigInt) -> [Byte] {
		let positiveSecret = sharedSecret.magnitude
		var bytes = positiveSecret.toArray()
		while bytes.count > 1 && bytes.first == 0 {
			bytes.removeFirst()
		}
		let minLength = 32  // 256 bits minimum for security
		if bytes.count < minLength {
			let padding = [Byte](repeating: 0, count: minLength - bytes.count)
			bytes = padding + bytes
		}

		return bytes
	}
}
