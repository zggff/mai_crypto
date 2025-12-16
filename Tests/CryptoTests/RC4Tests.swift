import BigInt
import Testing

@testable import Crypto

@Suite("Diffie")
struct RC4Tests {
	@Test("Test RC4")
	func rc4Test() {
        var rc4 = RC4()
        let key = Array("RC4 key".utf8)
        for n in (1...10) {
			let data = Array.random(size: n * 60)
            rc4.setKey(key: key)
			let encrypted = rc4.encrypt(data: data)
            rc4.reset()
			let decrypted = rc4.encrypt(data: encrypted)
			#expect(decrypted == data, "\(data)")
		}
    }
}
