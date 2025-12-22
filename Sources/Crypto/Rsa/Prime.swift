import BigInt
import Foundation

public class AbstractPrimeTest {
	let math = RsaMath.self

	let minProbability: Double

	public init(minProbability: Double) {
		precondition(minProbability >= 0.5 && minProbability < 1.0)
		self.minProbability = minProbability
	}

	public func isProbablyPrime(_ n: BigInt, randomBitGenerator: (Int) -> BigInt = randomBigInt)
		-> Bool
	{
		if n < 2 { return false }
		if n == 2 || n == 3 { return true }
		if n % 2 == 0 { return false }
		let errorPerIteration = self.errorProbabilityPerIteration()
		let requiredIterations = iterationsNeededToReachProbability(
			minProb: minProbability, perIterError: errorPerIteration)
		for _ in 0..<requiredIterations {
			let a = randomInRange(2, n - 2, randomBitGenerator: randomBitGenerator)
			if !singleIteration(n: n, rand: { a }) { return false }
		}
		return true
	}

	func errorProbabilityPerIteration() -> Double {
		return 0.5
	}

	func iterationsNeededToReachProbability(minProb: Double, perIterError: Double) -> Int {
		if perIterError <= 0 { return 1 }
		let numerator = log(1 - minProb)
		let denom = log(perIterError)
		let k = Int(ceil(numerator / denom))
		return max(1, k)
	}

	func randomInRange(
		_ lo: BigInt, _ hi: BigInt, randomBitGenerator: (Int) -> BigInt
	) -> BigInt {
		precondition(lo <= hi)
		let range = hi - lo + 1
		let r: BigInt = abs(randomBitGenerator(hi.bitWidth) % range)
		return lo + r
	}

	func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		fatalError("override")
	}

	public static func randomBigInt(bitLength: Int) -> BigInt {
		var rng = SystemRandomNumberGenerator()
		return randomBigInt(bitLength: bitLength, rand: &rng)
	}

	public static func randomBigInt(bitLength: Int, rand: inout SystemRandomNumberGenerator)
		-> BigInt
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
		return BigInt(Data(data))
	}
	public static func sieve(limit: Int) -> [BigInt] {
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

	}
}

public class FermatTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		let res = RsaMath.modPow(a, n - 1, n)
		return res == 1
	}
	override func errorProbabilityPerIteration() -> Double { return 0.5 }
}

public class SolovayStrassenTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		let x = RsaMath.modPow(a, (n - 1) / 2, n)
		var j = BigInt(RsaMath.jacobiSymbol(a: a, n: n))
		if j < 0 {
			j = n - 1
		}

		return x == j
	}
	override func errorProbabilityPerIteration() -> Double { return 0.5 }
}

public class MillerRabinTest: AbstractPrimeTest {
	override func singleIteration(n: BigInt, rand: () -> BigInt) -> Bool {
		let a = rand()
		var d = n - 1
		var s = 0
		while d % 2 == 0 {
			d >>= 1
			s += 1
		}
		var x = RsaMath.modPow(a, d, n)
		if x == 1 || x == n - 1 { return true }
		for _ in 1..<s {
			x = (x * x) % n
			if x == n - 1 { return true }
		}
		return false
	}
	override func errorProbabilityPerIteration() -> Double { return 0.25 }
}
