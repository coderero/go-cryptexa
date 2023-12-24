package tools

// @HashParams is a struct that holds the parameters for the hash function.
// The parameters are:
// @Cost: The log2 of the number of iterations of the hash function. The work factor therefore
// increases as 2^Cost. The default value is 14 and the minimum value is 30.
//
// @Rounds: The number of rounds of hashing to apply.
//
// @Parallelism: The degree of parallelism of the hashing function.
//
// NOTE: Rounds and Parallelism should follow the following equation:
// r * p < 2^30 as per the scrypt specification.
//
// @SaltLength: The length of the salt in bytes.
//
// @DKLen: The length of the derived key in bytes.
//
// @Salt: The salt to be used for hashing. The default value is a randomly generated salt but a
// @custom salt can be provided.
//
// @HashKey: The key to be used for identifying hashing. The default value is cryptexa.
//
// @SaltSeprarator: The separator to be used for separating the salt and the hash. The default value
// @is empty and salt is extracted from the length of the hash.
type HashParams struct {
	Cost           int
	Rounds         int
	Parallelism    int
	SaltLength     int
	DKLen          int
	Salt           []byte
	Identifier     string
	SaltSeprarator string
}
