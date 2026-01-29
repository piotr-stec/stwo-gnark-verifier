// This minimal implementation of the Stwo channel API for Blake2s comes from:
// https://github.com/starkware-libs/stwo-cairo/blob/main/stwo_cairo_verifier/crates/verifier_core/src/channel/blake2s.cairo

package channel

import (
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/HerodotusDev/stwo-gnark-verifier/blake2s"
	"github.com/HerodotusDev/stwo-gnark-verifier/m31"
	"github.com/HerodotusDev/stwo-gnark-verifier/utils"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/math/cmp"
	"github.com/consensys/gnark/std/math/uints"
)

// Blake2sHash is a 256-bit hash.
// TODO: at many places in the code we rather use [32]uints.U8, perhaps there should be a hash type handling both.
type Blake2sHash [8]uints.U32

// TranscriptTime tracks the number of challenges and sent messages.
type TranscriptTime struct {
	nChallenges uints.U32
	nSent       uints.U32
}

// incChallenges bumps the number of issued challenges.
func (ct *TranscriptTime) incChallenges(uapi *uints.BinaryField[uints.U32]) {
	ct.nChallenges = uapi.Add(ct.nChallenges, uints.NewU32(1))
	ct.nSent = uints.NewU32(0)
}

// incSent bumps the counter used for deriving fresh randomness.
func (ct *TranscriptTime) incSent(uapi *uints.BinaryField[uints.U32]) {
	ct.nSent = uapi.Add(ct.nSent, uints.NewU32(1))
}

// Channel is the Fiat-Shamir channel transcript.
type Channel struct {
	api         frontend.API
	blake2sChip *blake2s.Blake2sChip
	m31Chip     *m31.M31Chip
	uapi        *uints.BinaryField[uints.U32]
	comparator  *cmp.BoundedComparator

	digest      Blake2sHash
	channelTime TranscriptTime
}

// Digest returns the current digest of the channel. Useful for debugging.
func (c *Channel) Digest() Blake2sHash {
	return c.digest
}

// ╔══════════════════════════════════╗
// ║           Constructor            ║
// ╚══════════════════════════════════╝

// NewChannel builds a Blake2s transcript channel chip.
func NewChannel(api frontend.API) *Channel {
	blake2sChip := blake2s.NewBlake2sChip(api)
	m31Chip := m31.NewM31Chip(api)
	uapi, err := uints.New[uints.U32](api)
	if err != nil {
		panic(err)
	}
	comparator := cmp.NewBoundedComparator(api, big.NewInt(1<<32), false)

	return &Channel{
		api:         api,
		blake2sChip: blake2sChip,
		m31Chip:     m31Chip,
		uapi:        uapi,
		comparator:  comparator,
		digest:      zeroHash(),
		channelTime: TranscriptTime{
			nChallenges: uints.NewU32(0),
			nSent:       uints.NewU32(0),
		},
	}
}

// InitializeWith initializes the channel with a specific digest and nDraws
// This is analogous to Solidity's initializeWith for generic verification
func (c *Channel) InitializeWith(digest [8]frontend.Variable, nDraws frontend.Variable) {
	// Convert digest from frontend.Variable to uints.U32
	var digestU32 [8]uints.U32
	for i := 0; i < 8; i++ {
		digestU32[i] = c.uapi.ValueOf(digest[i])
	}

	// DEBUG: Print incoming digest in hex
	bytes := make([]byte, 32)
	for i := 0; i < 8; i++ {
		word := digestU32[i]
		for j := 0; j < 4; j++ {
			val := word[j].Val
			var byteVal byte
			switch v := val.(type) {
			case int:
				byteVal = byte(v)
			case *big.Int:
				byteVal = byte(v.Uint64())
			case uint64:
				byteVal = byte(v)
			default:
				byteVal = 0
			}
			bytes[i*4+j] = byteVal
		}
	}
	fmt.Printf("DEBUG InitializeWith: incoming digest = 0x%s\n", hex.EncodeToString(bytes))

	// Use digest directly as Blake2sHash (already in correct format)
	c.digest = digestU32
	c.channelTime = TranscriptTime{
		nChallenges: uints.NewU32(0),
		nSent:       c.uapi.ValueOf(nDraws),
	}

	// DEBUG: Print after initialization
	c.DebugPrint("After initialization")
}

// ╔══════════════════════════════════╗
// ║           Mix Operations         ║
// ╚══════════════════════════════════╝

// MixRoot absorbs a Merkle root into the running transcript digest.
func (c *Channel) MixRoot(root Blake2sHash) {
	msg := c.hashToBytes(c.digest)
	msg = append(msg, c.hashToBytes(root)...)
	c.updateDigest(c.computeDigest(msg))
}

// MixRootBytes absorbs a byte array into the running transcript digest.
func (c *Channel) MixRootBytes(root []uints.U8) {
	msg := c.hashToBytes(c.digest)
	msg = append(msg, root...)
	c.updateDigest(c.computeDigest(msg))
}

// MixRootBytesVar mixes root bytes from frontend.Variable slice into the digest
func (c *Channel) MixRootBytesVar(rootVar []frontend.Variable) {
	// DEBUG: Check incoming values
	fmt.Printf("DEBUG MixRootBytesVar: len(rootVar)=%d, rootVar[0]=%v, rootVar[1]=%v\n", len(rootVar), rootVar[0], rootVar[1])

	// Convert frontend.Variable to uints.U8
	bapi, err := uints.NewBytes(c.api)
	if err != nil {
		panic(err)
	}
	root := make([]uints.U8, len(rootVar))
	for i, v := range rootVar {
		root[i] = bapi.ValueOf(v)
	}

	// DEBUG: Check converted values
	fmt.Printf("DEBUG MixRootBytesVar after convert: root[0]=%v, root[1]=%v\n", root[0], root[1])

	c.MixRootBytes(root)
}

// MixFelts absorbs secure field elements into the digest.
func (c *Channel) MixFelts(felts []m31.QM31) {
	msg := c.hashToBytes(c.digest)
	for _, felt := range felts {
		msg = append(msg, c.qm31ToBytes(felt)...)
	}
	c.updateDigest(c.computeDigest(msg))
}

// MixU64 absorbs a 64-bit nonce by splitting it into two u32 words.
func (c *Channel) MixU64(nonce uints.U64) {
	lo := c.uapi.PackLSB(nonce[0], nonce[1], nonce[2], nonce[3])
	hi := c.uapi.PackLSB(nonce[4], nonce[5], nonce[6], nonce[7])
	c.MixU32s([]uints.U32{lo, hi})
}

// MixU32s absorbs a slice of u32 values into the digest.
func (c *Channel) MixU32s(data []uints.U32) {
	msg := c.hashToBytes(c.digest)
	for _, value := range data {
		msg = append(msg, c.uapi.UnpackLSB(value)...)
	}
	c.updateDigest(c.computeDigest(msg))
}

// ╔══════════════════════════════════╗
// ║           Random Draws           ║
// ╚══════════════════════════════════╝

// DrawFelt samples a single QM31 element from the channel.
func (c *Channel) DrawFelt() m31.QM31 {
	felts := c.drawRandomBaseFelts()
	return m31.NewQM31FromComponents(felts[0], felts[1], felts[2], felts[3])
}

// DrawFelts samples n QM31 elements, drawing base-field limbs in pairs.
func (c *Channel) DrawFelts(n int) []m31.QM31 {
	if n <= 0 {
		return nil
	}

	res := make([]m31.QM31, 0, n)
	for len(res) < n {
		base := c.drawRandomBaseFelts()
		res = append(res, m31.NewQM31FromComponents(base[0], base[1], base[2], base[3]))
		if len(res) == n {
			break
		}
		res = append(res, m31.NewQM31FromComponents(base[4], base[5], base[6], base[7]))
	}

	return res
}

// DrawRandomBytes exposes the next 32 pseudorandom bytes from the channel.
func (c *Channel) DrawRandomBytes() []uints.U8 {
	words := c.drawRandomWords()
	bytes := make([]uints.U8, 0, 32)
	for _, word := range words {
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// ╔══════════════════════════════════╗
// ║        Proof of Work Checks      ║
// ╚══════════════════════════════════╝

// MixAndCheckPowNonce mixes a nonce and checks the leading zero bits.
func (c *Channel) MixAndCheckPowNonce(nonce uints.U64, interactionPowBits int) {
	c.MixU64(nonce)
	c.checkProofOfWork(nonce, interactionPowBits)
}

// CheckPowNonce verifies the proof of work without mixing the nonce.
// This matches Rust's verify_pow_nonce implementation:
// 1. Computes H1 = Hash(POW_PREFIX || [0; 24] || digest || n_bits)
// 2. Computes H2 = Hash(H1 || nonce)
// 3. Checks that H2 has at least n_bits trailing zeros
func (c *Channel) CheckPowNonce(nonce uints.U64, interactionPowBits int) {
	c.checkProofOfWork(nonce, interactionPowBits)
}

// checkProofOfWork implements the proof of work verification matching Rust's verify_pow_nonce.
// Verifies that H(H(POW_PREFIX, [0_u8; 24], digest, n_bits), nonce) has at least n_bits trailing zeros.
func (c *Channel) checkProofOfWork(nonce uints.U64, nBits int) {
	const POW_PREFIX uint32 = 0x12345678

	// Step 1: Compute H(POW_PREFIX, [0; 24], digest, n_bits)
	msg1 := make([]uints.U8, 0, 4+24+32+4)

	// Add POW_PREFIX (4 bytes, little-endian)
	powPrefixU32 := uints.NewU32(POW_PREFIX)
	msg1 = append(msg1, c.uapi.UnpackLSB(powPrefixU32)...)

	// Add 24 zero bytes
	for i := 0; i < 24; i++ {
		msg1 = append(msg1, uints.NewU8(0))
	}

	// Add current digest (32 bytes)
	msg1 = append(msg1, c.hashToBytes(c.digest)...)

	// Add n_bits (4 bytes, little-endian u32)
	nBitsU32 := uints.NewU32(uint32(nBits))
	msg1 = append(msg1, c.uapi.UnpackLSB(nBitsU32)...)

	prefixedDigest := c.computeDigest(msg1)

	// Step 2: Compute H(prefixed_digest, nonce)
	msg2 := c.hashToBytes(prefixedDigest)
	// nonce is U64 = [8]U8, append all 8 bytes
	for i := 0; i < 8; i++ {
		msg2 = append(msg2, nonce[i])
	}

	result := c.computeDigest(msg2)

	// Step 3: Check trailing zeros
	// The result is 32 bytes = 256 bits
	// We need to check if the first n_bits are zero (in little-endian byte order)
	// This means checking trailing zeros when interpreted as u128/u256 little-endian

	// For simplicity, check the required number of bits in the first words
	bitsToCheck := nBits
	for i := 0; i < 8 && bitsToCheck > 0; i++ {
		word := result[i]
		if bitsToCheck >= 32 {
			// Entire word must be zero
			c.uapi.AssertEq(word, uints.NewU32(0))
			bitsToCheck -= 32
		} else {
			// Only some bits of this word must be zero
			mask := uints.NewU32((1 << bitsToCheck) - 1)
			masked := c.uapi.And(word, mask)
			c.uapi.AssertEq(masked, uints.NewU32(0))
			bitsToCheck = 0
		}
	}
}

// ╔══════════════════════════════════╗
// ║              Queries             ║
// ╚══════════════════════════════════╝

// GenerateBaseLayerQueries the largest layer of queries used by the verifier (folding happens outside of this function)
// This matches Rust's Queries::generate which uses BTreeSet for automatic deduplication and sorting
func (c *Channel) GenerateBaseLayerQueries(maxLogSize frontend.Variable, nQueries uint8) []frontend.Variable {
	fmt.Printf("Max log size in generate = %v, nQueries=%v", maxLogSize, nQueries)
	
	// Generate queries (potentially with duplicates)
	queries := make([]frontend.Variable, 0)
	queryCount := uint8(0)
	maxQuery := c.api.Sub(utils.Pow(c.api, c.comparator, frontend.Variable(2), maxLogSize), frontend.Variable(1))
	maxQueryU32 := c.uapi.ValueOf(maxQuery)
	
	// Generate enough queries to handle potential duplicates
	nDuplicates := uint8(0)
	for queryCount < nQueries+nDuplicates {
		randomBytes := c.DrawRandomBytes()
		for i := 0; i < len(randomBytes); i += 4 {
			query := c.uapi.PackLSB(randomBytes[i], randomBytes[i+1], randomBytes[i+2], randomBytes[i+3])
			quotientQuery := c.uapi.And(query, maxQueryU32)
			queries = append(queries, c.uapi.ToValue(quotientQuery))
			queryCount++
			if queryCount == nQueries+nDuplicates {
				break
			}
		}
	}
	
	// Deduplicate and sort queries (matching Rust's BTreeSet behavior)
	queriesDeduped, err := c.api.Compiler().NewHint(utils.DeduplicationHint, int(nQueries), queries...)
	if err != nil {
		panic(err)
	}
	queriesSorted, err := c.api.Compiler().NewHint(utils.AscendingOrderHint, int(nQueries), queriesDeduped...)
	if err != nil {
		panic(err)
	}
	
	// Verify the deduplication and sorting
	utils.AssertPartialDeduplication(c.api, queriesSorted, queries)
	utils.AssertAscendingOrder(c.api, queriesSorted)
	
	return queriesSorted
}

// ╔══════════════════════════════════╗
// ║           Helper Methods         ║
// ╚══════════════════════════════════╝

// updateDigest stores the new digest and updates bookkeeping.
func (c *Channel) updateDigest(newDigest Blake2sHash) {
	c.digest = newDigest
	c.channelTime.incChallenges(c.uapi)
}

// drawRandomBaseFelts samples eight base-field elements for QM31 packing.
func (c *Channel) drawRandomBaseFelts() [8]m31.M31 {
	words := c.drawRandomWords()
	var felts [8]m31.M31
	for i, word := range words {
		val := c.uapi.ToValue(word)
		felts[i] = c.m31Chip.FullReduce(m31.NewM31Unchecked(val))
	}
	return felts
}

// drawRandomWords derives a fresh Blake2s hash from the digest and counter.
func (c *Channel) drawRandomWords() Blake2sHash {
	msg := c.hashToBytes(c.digest)
	msg = append(msg, c.uapi.UnpackLSB(c.channelTime.nSent)...)

	msg = append(msg, uints.NewU8(0))

	c.channelTime.incSent(c.uapi)

	return c.computeDigest(msg)
}

// hashToBytes flattens a Blake2s hash into a byte slice.
func (c *Channel) hashToBytes(hash Blake2sHash) []uints.U8 {
	bytes := make([]uints.U8, 0, 32)
	for _, word := range hash {
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// qm31ToBytes encodes a QM31 element as sixteen little-endian bytes.
func (c *Channel) qm31ToBytes(felt m31.QM31) []uints.U8 {
	comps := felt.Components()
	bytes := make([]uints.U8, 0, 16)
	for _, comp := range comps {
		word := c.uapi.ValueOf(comp.Variable())
		bytes = append(bytes, c.uapi.UnpackLSB(word)...)
	}
	return bytes
}

// computeDigest hashes the message and returns the digest as eight u32 words.
func (c *Channel) computeDigest(msg []uints.U8) Blake2sHash {
	state, _ := c.blake2sChip.Blake2s(msg)
	return Blake2sHash(state.H)
}

// zeroHash returns the zero-initialized Blake2s hash.
func zeroHash() Blake2sHash {
	var hash Blake2sHash
	for i := range hash {
		hash[i] = uints.NewU32(0)
	}
	return hash
}

// DebugPrint prints the current state of the channel for debugging
func (c *Channel) DebugPrint(label string) {
	fmt.Printf("\n=== Channel Debug: %s ===\n", label)

	// Convert digest to byte array for hex encoding
	bytes := make([]byte, 32) // 8 words * 4 bytes each
	for i := 0; i < 8; i++ {
		// Extract bytes from each U32 word (little-endian within word)
		word := c.digest[i]
		for j := 0; j < 4; j++ {
			// Try different types that Val can be
			val := word[j].Val
			var byteVal byte
			switch v := val.(type) {
			case int:
				byteVal = byte(v)
			case *big.Int:
				byteVal = byte(v.Uint64())
			case uint64:
				byteVal = byte(v)
			default:
				byteVal = 0
			}
			bytes[i*4+j] = byteVal
		}
	}

	// Print as hex string (this will be in little-endian word order)
	fmt.Printf("Digest: 0x%s\n", hex.EncodeToString(bytes))

	// Also print in big-endian order for comparison with reference implementations
	bytesReversed := make([]byte, 32)
	for i := 0; i < 8; i++ {
		word := c.digest[7-i]
		for j := 0; j < 4; j++ {
			val := word[3-j].Val
			var byteVal byte
			switch v := val.(type) {
			case int:
				byteVal = byte(v)
			case *big.Int:
				byteVal = byte(v.Uint64())
			case uint64:
				byteVal = byte(v)
			default:
				byteVal = 0
			}
			bytesReversed[i*4+j] = byteVal
		}
	}
	fmt.Printf("Digest (big-endian): 0x%s\n", hex.EncodeToString(bytesReversed))

	fmt.Printf("nChallenges: %v, nSent: %v\n", c.channelTime.nChallenges, c.channelTime.nSent)
	fmt.Println("=====================================\n")
}
