package pkg

// The `type HashParams` is defining a struct. This struct has five fields:
// `Cost`, `Rounds`, `Parallelism`, `SaltLength`, and `DKLen`. Each field has a specific data type,
// such as `int`. This struct can be used to store and manipulate values related to hash parameters.
type HashParams struct {
	Cost        int
	Rounds      int
	Parallelism int
	SaltLength  int
	DKLen       int
	SignerKey   string
}
