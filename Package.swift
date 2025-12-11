// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
	name: "Cryptography",
	platforms: [.macOS(.v26)],
	products: [
		// Products define the executables and libraries a package produces, making them visible to other packages.
		.library(
			name: "Symmetric",
			targets: ["Symmetric"]
		),
		.library(
			name: "Rsa",
			targets: ["Rsa"]
		),
		.library(
			name: "Aes",
			targets: ["Aes"]
		),
		.executable(name: "Main", targets: ["Main"]),
		.executable(name: "DesCmd", targets: ["DesCmd"]),
	],
	dependencies: [
		.package(url: "https://github.com/attaswift/BigInt.git", from: "5.4.0")
	],
	targets: [
		// Targets are the basic building blocks of a package, defining a module or a test suite.
		// Targets can depend on other targets in this package and products from dependencies.
		.target(
			name: "Symmetric"
		),
		.target(
			name: "Rsa",
			dependencies: [.product(name: "BigInt", package: "BigInt")]
		),
		.target(
			name: "Aes",
			dependencies: [
				.product(name: "BigInt", package: "BigInt"),
				"Symmetric",
			]
		),
		.executableTarget(
			name: "Main",
			dependencies: ["Symmetric", "Rsa", "Aes"],
		),
		.executableTarget(
			name: "DesCmd",
			dependencies: ["Symmetric"],
		),

		.testTarget(
			name: "SymmetricTests",
			dependencies: ["Symmetric"]
		),
		.testTarget(
			name: "RsaTests",
			dependencies: ["Rsa"]
		),
		.testTarget(
			name: "AesTests",
			dependencies: ["Aes"]
		),
	]
)
