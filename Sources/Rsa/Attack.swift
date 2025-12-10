import BigInt
import Foundation

public struct RsaAttackService {
	public struct RsaCandidate {
		public let k: BigInt
		public let d: BigInt  // k/d
		public let phi: BigInt?
		public let p: BigInt?
		public let q: BigInt?
	}

	public struct RsaAttackResult {
		public let d: BigInt?
		public let phi: BigInt?
		public let candidates: [RsaCandidate]
	}

	public init() {}
	public func attack(key: RsaService.PublicKey) -> RsaAttackResult {
		let e = key.e
		let n = key.n
		let cf = continuedFraction(numerator: e, denominator: n)
		let convergents = convergentsFromContinuedFraction(cf)

		var candidates: [RsaCandidate] = []
		var foundD: BigInt? = nil
		var foundPhi: BigInt? = nil

		for (k, d) in convergents {
			if k == 0 { continue }
			let edMinus1 = e * d - 1
			if edMinus1 <= 0 { continue }
			if edMinus1 % k != 0 { continue }

			let phiCandidate = edMinus1 / k

			let s = n - phiCandidate + 1
			let discr = s * s - 4 * n
			if discr < 0 {
				let cand = RsaCandidate(
					k: k,
					d: d,
					phi: phiCandidate,
					p: nil, q: nil)
				candidates.append(cand)
				continue
			}
			if let sqrtD = integerSqrtIfPerfectSquare(discr) {
				// p = (s + sqrtD)/2, q = (s - sqrtD)/2
				if (s + sqrtD) % 2 == 0 && (s - sqrtD) % 2 == 0 {
					let p = (s + sqrtD) / 2
					let q = (s - sqrtD) / 2
					if p > 0 && q > 0 && p * q == n {
						let cand = RsaCandidate(
							k: k,
							d: d,
							phi: phiCandidate,
							p: p, q: q)
						candidates.append(cand)
						foundD = d
						foundPhi = phiCandidate
						break
					} else {
						let cand = RsaCandidate(
							k: k,
							d: d,
							phi: phiCandidate,
							p: p, q: q)
						candidates.append(cand)
					}
				} else {
					let cand = RsaCandidate(
						k: k,
						d: d,
						phi: phiCandidate,
						p: nil, q: nil)
					candidates.append(cand)
				}
			} else {
				let cand = RsaCandidate(
					k: k,
					d: d,
					phi: phiCandidate,
					p: nil, q: nil)
				candidates.append(cand)
			}
		}

		return RsaAttackResult(d: foundD, phi: foundPhi, candidates: candidates)
	}

	public func continuedFraction(numerator: BigInt, denominator: BigInt) -> [BigInt] {
		var n = numerator
		var d = denominator
		var cf: [BigInt] = []

		while d != 0 {
			let q = n / d
			let r = n % d
			cf.append(q)
			n = d
			d = r
		}
		return cf
	}
	public func convergentsFromContinuedFraction(_ cf: [BigInt]) -> [(BigInt, BigInt)] {
		var convergents: [(BigInt, BigInt)] = []

		var pPrev2 = BigInt(0)
		var pPrev1 = BigInt(1)
		var qPrev2 = BigInt(1)
		var qPrev1 = BigInt(0)

		for ai in cf {
			let p = ai * pPrev1 + pPrev2
			let q = ai * qPrev1 + qPrev2

			convergents.append((p, q))

			pPrev2 = pPrev1
			pPrev1 = p
			qPrev2 = qPrev1
			qPrev1 = q
		}
		return convergents
	}

	public func integerSqrtIfPerfectSquare(_ x: BigInt) -> BigInt? {
		if x < 0 { return nil }
		if x == 0 || x == 1 { return x }

		var low = BigInt(1)
		var high = x
		let bitW = x.bitWidth
		let approx = BigInt(1) << (bitW / 2 + 1)
		if approx < high { high = approx }

		while low <= high {
			let mid = (low + high) >> 1
			let sq = mid * mid
			if sq == x {
				return mid
			} else if sq < x {
				low = mid + 1
			} else {
				high = mid - 1
			}
		}
		return nil
	}
}
