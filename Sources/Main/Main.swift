import Crypto
import Foundation

@main
struct Main {
	static func main() async throws {
        print(GF256.irreducible(0b1111))
        print(GF256.degree(0b1111))
	}
}

struct Main2 {
	static func main() async throws {
        var from = "test.txt"
        var to = "enc2.test.txt"

        from = "enc2.test.txt"
        to = "dec2.test.txt"
		guard let input = InputStream(fileAtPath: from) else {
			throw EncryptionError.fileOpen("failed to open path: '\(from)'")
		}
		FileManager.default.createFile(atPath: to, contents: nil)
		guard let output = OutputStream(toFileAtPath: to, append: false) else {
			throw EncryptionError.fileOpen("failed to open path: '\(to)'")
		}
		defer {
			input.close()
			output.close()
		}
        let key = Array("hello this is a key".utf8)
        var rc = RC4()
        rc.setKey(key: key)
        try rc.encrypt(in: input, out: output)
	}
}

