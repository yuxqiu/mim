use crate::hash::prf::constraints::PRFGadget;
use ark_ff::PrimeField;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

// 2.1.  Parameters
// The following table summarizes various parameters and their ranges:
//               | BLAKE2b          | BLAKE2s          |
// --------------+------------------+------------------+
// Bits in word  | w = 64           | w = 32           |
// Rounds in F   | r = 12           | r = 10           |
// Block bytes   | bb = 128         | bb = 64          |
// Hash bytes    | 1 <= nn <= 64    | 1 <= nn <= 32    |
// Key bytes     | 0 <= kk <= 64    | 0 <= kk <= 32    |
// Input bytes   | 0 <= ll < 2**128 | 0 <= ll < 2**64  |
// --------------+------------------+------------------+
// G Rotation    | (R1, R2, R3, R4) | (R1, R2, R3, R4) |
// constants =   | (32, 24, 16, 63) | (16, 12,  8,  7) |
// --------------+------------------+------------------+
//

const R1: usize = 16;
const R2: usize = 12;
const R3: usize = 8;
const R4: usize = 7;

// Round     |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 |
// ----------+-------------------------------------------------+
// SIGMA[0]  |  0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15 |
// SIGMA[1]  | 14 10  4  8  9 15 13  6  1 12  0  2 11  7  5  3 |
// SIGMA[2]  | 11  8 12  0  5  2 15 13 10 14  3  6  7  1  9  4 |
// SIGMA[3]  |  7  9  3  1 13 12 11 14  2  6  5 10  4  0 15  8 |
// SIGMA[4]  |  9  0  5  7  2  4 10 15 14  1 11 12  6  8  3 13 |
// SIGMA[5]  |  2 12  6 10  0 11  8  3  4 13  7  5 15 14  1  9 |
// SIGMA[6]  | 12  5  1 15 14 13  4 10  0  7  6  3  9  2  8 11 |
// SIGMA[7]  | 13 11  7 14 12  1  3  9  5  0 15  4  8  6  2 10 |
// SIGMA[8]  |  6 15 14  9 11  3  0  8 12  2 13  7  1  4 10  5 |
// SIGMA[9]  | 10  2  8  4  7  6  1  5 15 11  9 14  3 12 13  0 |
// ----------+-------------------------------------------------+
//

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

// 3.1.  Mixing Function G
// The G primitive function mixes two input words, "x" and "y", into
// four words indexed by "a", "b", "c", and "d" in the working vector
// v[0..15].  The full modified vector is returned.  The rotation
// constants (R1, R2, R3, R4) are given in Section 2.1.
// FUNCTION G( v[0..15], a, b, c, d, x, y )
// |
// |   v[a] := (v[a] + v[b] + x) mod 2**w
// |   v[d] := (v[d] ^ v[a]) >>> R1
// |   v[c] := (v[c] + v[d])     mod 2**w
// |   v[b] := (v[b] ^ v[c]) >>> R2
// |   v[a] := (v[a] + v[b] + y) mod 2**w
// |   v[d] := (v[d] ^ v[a]) >>> R3
// |   v[c] := (v[c] + v[d])     mod 2**w
// |   v[b] := (v[b] ^ v[c]) >>> R4
// |
// |   RETURN v[0..15]
// |
// END FUNCTION.
//

fn mixing_g<ConstraintF: PrimeField>(
    v: &mut [UInt32<ConstraintF>],
    a: usize,
    b: usize,
    c: usize,
    d: usize,
    x: &UInt32<ConstraintF>,
    y: &UInt32<ConstraintF>,
) -> Result<(), SynthesisError> {
    v[a] = UInt32::wrapping_add_many(&[v[a].clone(), v[b].clone(), x.clone()])?;
    v[d] = (&v[d] ^ &v[a]).rotate_right(R1);
    v[c] = v[c].wrapping_add(&v[d]);
    v[b] = (&v[b] ^ &v[c]).rotate_right(R2);
    v[a] = UInt32::wrapping_add_many(&[v[a].clone(), v[b].clone(), y.clone()])?;
    v[d] = (&v[d] ^ &v[a]).rotate_right(R3);
    v[c] = v[c].wrapping_add(&v[d]);
    v[b] = (&v[b] ^ &v[c]).rotate_right(R4);

    Ok(())
}

// 3.2.  Compression Function F
// Compression function F takes as an argument the state vector "h",
// message block vector "m" (last block is padded with zeros to full
// block size, if required), 2w-bit offset counter "t", and final block
// indicator flag "f".  Local vector v[0..15] is used in processing.  F
// returns a new state vector.  The number of rounds, "r", is 12 for
// BLAKE2b and 10 for BLAKE2s.  Rounds are numbered from 0 to r - 1.
// FUNCTION F( h[0..7], m[0..15], t, f )
// |
// |      // Initialize local work vector v[0..15]
// |      v[0..7] := h[0..7]              // First half from state.
// |      v[8..15] := IV[0..7]            // Second half from IV.
// |
// |      v[12] := v[12] ^ (t mod 2**w)   // Low word of the offset.
// |      v[13] := v[13] ^ (t >> w)       // High word.
// |
// |      IF f = TRUE THEN                // last block flag?
// |      |   v[14] := v[14] ^ 0xFF..FF   // Invert all bits.
// |      END IF.
// |
// |      // Cryptographic mixing
// |      FOR i = 0 TO r - 1 DO           // Ten or twelve rounds.
// |      |
// |      |   // Message word selection permutation for this round.
// |      |   s[0..15] := SIGMA[i mod 10][0..15]
// |      |
// |      |   v := G( v, 0, 4,  8, 12, m[s[ 0]], m[s[ 1]] )
// |      |   v := G( v, 1, 5,  9, 13, m[s[ 2]], m[s[ 3]] )
// |      |   v := G( v, 2, 6, 10, 14, m[s[ 4]], m[s[ 5]] )
// |      |   v := G( v, 3, 7, 11, 15, m[s[ 6]], m[s[ 7]] )
// |      |
// |      |   v := G( v, 0, 5, 10, 15, m[s[ 8]], m[s[ 9]] )
// |      |   v := G( v, 1, 6, 11, 12, m[s[10]], m[s[11]] )
// |      |   v := G( v, 2, 7,  8, 13, m[s[12]], m[s[13]] )
// |      |   v := G( v, 3, 4,  9, 14, m[s[14]], m[s[15]] )
// |      |
// |      END FOR
// |
// |      FOR i = 0 TO 7 DO               // XOR the two halves.
// |      |   h[i] := h[i] ^ v[i] ^ v[i + 8]
// |      END FOR.
// |
// |      RETURN h[0..7]                  // New state.
// |
// END FUNCTION.
//

#[allow(clippy::cast_possible_truncation)]
fn blake2s_compression<ConstraintF: PrimeField>(
    h: &mut [UInt32<ConstraintF>],
    m: &[UInt32<ConstraintF>],
    t: u64,
    f: bool,
) -> Result<(), SynthesisError> {
    assert_eq!(h.len(), 8);
    assert_eq!(m.len(), 16);

    // static const uint32_t blake2s_iv[8] =
    // {
    // 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    // 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    // };
    //

    let mut v = Vec::with_capacity(16);
    v.extend_from_slice(h);
    v.push(UInt32::constant(0x6A09E667));
    v.push(UInt32::constant(0xBB67AE85));
    v.push(UInt32::constant(0x3C6EF372));
    v.push(UInt32::constant(0xA54FF53A));
    v.push(UInt32::constant(0x510E527F));
    v.push(UInt32::constant(0x9B05688C));
    v.push(UInt32::constant(0x1F83D9AB));
    v.push(UInt32::constant(0x5BE0CD19));

    assert_eq!(v.len(), 16);

    v[12] ^= t as u32;
    v[13] ^= (t >> 32) as u32;

    if f {
        v[14] ^= u32::MAX;
    }

    for i in 0..10 {
        let s = SIGMA[i % 10];

        mixing_g(&mut v, 0, 4, 8, 12, &m[s[0]], &m[s[1]])?;
        mixing_g(&mut v, 1, 5, 9, 13, &m[s[2]], &m[s[3]])?;
        mixing_g(&mut v, 2, 6, 10, 14, &m[s[4]], &m[s[5]])?;
        mixing_g(&mut v, 3, 7, 11, 15, &m[s[6]], &m[s[7]])?;
        mixing_g(&mut v, 0, 5, 10, 15, &m[s[8]], &m[s[9]])?;
        mixing_g(&mut v, 1, 6, 11, 12, &m[s[10]], &m[s[11]])?;
        mixing_g(&mut v, 2, 7, 8, 13, &m[s[12]], &m[s[13]])?;
        mixing_g(&mut v, 3, 4, 9, 14, &m[s[14]], &m[s[15]])?;
    }

    for i in 0..8 {
        h[i] ^= &v[i];
        h[i] ^= &v[i + 8];
    }

    Ok(())
}

// FUNCTION BLAKE2( d[0..dd-1], ll, kk, nn )
// |
// |     h[0..7] := IV[0..7]          // Initialization Vector.
// |
// |     // Parameter block p[0]
// |     h[0] := h[0] ^ 0x01010000 ^ (kk << 8) ^ nn
// |
// |     // Process padded key and data blocks
// |     IF dd > 1 THEN
// |     |       FOR i = 0 TO dd - 2 DO
// |     |       |       h := F( h, d[i], (i + 1) * bb, FALSE )
// |     |       END FOR.
// |     END IF.
// |
// |     // Final block.
// |     IF kk = 0 THEN
// |     |       h := F( h, d[dd - 1], ll, TRUE )
// |     ELSE
// |     |       h := F( h, d[dd - 1], ll + bb, TRUE )
// |     END IF.
// |
// |     RETURN first "nn" bytes from little-endian word array h[].
// |
// END FUNCTION.
//

pub struct Blake2sState<ConstraintF: PrimeField> {
    h: [UInt32<ConstraintF>; 8],
    // blake2s uses a LazyBuffer to optimize memory usage
    // maybe we can adapt that?
    buffer: Vec<Boolean<ConstraintF>>,
    t: u64,
}

impl<ConstraintF: PrimeField> Blake2sState<ConstraintF> {
    pub fn new() -> Result<Self, SynthesisError> {
        let h = [
            UInt32::constant(0x6A09E667 ^ (0x01010000 ^ 32)),
            UInt32::constant(0xBB67AE85),
            UInt32::constant(0x3C6EF372),
            UInt32::constant(0xA54FF53A),
            UInt32::constant(0x510E527F),
            UInt32::constant(0x9B05688C),
            UInt32::constant(0x1F83D9AB),
            UInt32::constant(0x5BE0CD19),
        ];

        Ok(Self {
            h,
            buffer: Vec::new(),
            t: 0,
        })
    }

    pub fn update(&mut self, input: &[Boolean<ConstraintF>]) -> Result<(), SynthesisError> {
        self.buffer.extend_from_slice(input);

        // if there are only multiple of 512 bytes, reserve it for next round
        // because we might want to compress it as the last block
        let mut buffer_end = (self.buffer.len() / 512) * 512;
        if self.buffer.len() % 512 == 0 {
            buffer_end = buffer_end.saturating_sub(512);
        }

        for block in self.buffer[..buffer_end].chunks(512) {
            let this_block: Vec<_> = block.chunks(32).map(UInt32::from_bits_le).collect();

            self.t += 64;
            blake2s_compression(&mut self.h, &this_block, self.t, false)?;
        }

        self.buffer.drain(..buffer_end);

        Ok(())
    }

    pub fn finalize(mut self) -> Result<[UInt32<ConstraintF>; 8], SynthesisError> {
        // hash the remaining bits in the buffer
        if !self.buffer.is_empty() {
            let mut final_block = Vec::with_capacity(16);

            for word in self.buffer.chunks(32) {
                let mut tmp = word.to_vec();
                while tmp.len() < 32 {
                    tmp.push(Boolean::constant(false));
                }
                final_block.push(UInt32::from_bits_le(&tmp));
            }

            while final_block.len() < 16 {
                final_block.push(UInt32::constant(0));
            }

            self.t += (self.buffer.len() / 8) as u64;
            blake2s_compression(&mut self.h, &final_block, self.t, true)?;
        }

        // if no input is consumed, hash a block of 0
        if self.t == 0 {
            let final_block = (0..16)
                .map(|_| UInt32::constant(0))
                .collect::<Vec<UInt32<ConstraintF>>>();
            blake2s_compression(&mut self.h, &final_block, self.t, true)?;
        }

        Ok(self.h)
    }
}

pub struct StatefulBlake2sGadget<F: PrimeField> {
    state: Blake2sState<F>,
}
#[derive(Clone, Debug)]
pub struct OutputVar<ConstraintF: PrimeField>(pub Vec<UInt8<ConstraintF>>);

impl<ConstraintF: PrimeField> EqGadget<ConstraintF> for OutputVar<ConstraintF> {
    #[tracing::instrument(target = "r1cs")]
    fn is_eq(&self, other: &Self) -> Result<Boolean<ConstraintF>, SynthesisError> {
        self.0.is_eq(&other.0)
    }

    /// If `should_enforce == true`, enforce that `self` and `other` are equal;
    /// else, enforce a vacuously true statement.
    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.0.conditional_enforce_equal(&other.0, should_enforce)
    }

    /// If `should_enforce == true`, enforce that `self` and `other` are not
    /// equal; else, enforce a vacuously true statement.
    #[tracing::instrument(target = "r1cs")]
    fn conditional_enforce_not_equal(
        &self,
        other: &Self,
        should_enforce: &Boolean<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        self.0
            .as_slice()
            .conditional_enforce_not_equal(other.0.as_slice(), should_enforce)
    }
}

impl<ConstraintF: PrimeField> ToBytesGadget<ConstraintF> for OutputVar<ConstraintF> {
    #[inline]
    fn to_bytes_le(&self) -> Result<Vec<UInt8<ConstraintF>>, SynthesisError> {
        Ok(self.0.clone())
    }
}

impl<F: PrimeField> PRFGadget<F> for StatefulBlake2sGadget<F> {
    type OutputVar = OutputVar<F>;
    const OUTPUT_SIZE: usize = 32;

    fn update(&mut self, input: &[UInt8<F>]) -> Result<(), SynthesisError> {
        let input_bits: Vec<_> = input.iter().flat_map(|b| b.to_bits_le().unwrap()).collect();
        self.state.update(&input_bits)
    }

    fn finalize(self) -> Result<<Self as PRFGadget<F>>::OutputVar, SynthesisError> {
        let result: Vec<_> = self
            .state
            .finalize()?
            .iter()
            .flat_map(|int| int.to_bytes_le().unwrap())
            .collect();
        Ok(OutputVar(result))
    }
}

impl<F: PrimeField> Default for StatefulBlake2sGadget<F> {
    fn default() -> Self {
        Self {
            state: Blake2sState::new().unwrap(),
        }
    }
}

#[cfg(test)]
mod test {
    use ark_bls12_381::Fq as Fr;
    use ark_std::rand::Rng;
    use blake2::digest;

    use crate::hash::prf::blake2s::constraints::Blake2sState;
    use crate::hash::prf::blake2s::constraints::OutputVar;
    use ark_ff::PrimeField;
    use ark_relations::r1cs::ConstraintSystem;
    use ark_relations::r1cs::SynthesisError;
    use blake2::Blake2s256;
    use digest::{Digest, FixedOutput};

    use super::StatefulBlake2sGadget;
    use ark_r1cs_std::prelude::*;

    fn evaluate_blake2s<ConstraintF: PrimeField>(
        input: &[Boolean<ConstraintF>],
    ) -> Result<[UInt32<ConstraintF>; 8], SynthesisError> {
        assert!(input.len() % 8 == 0);
        let mut state = Blake2sState::new()?;
        state.update(input)?;
        state.finalize()
    }

    #[test]
    fn test_blake2s_constraints() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let input_bits: Vec<_> = (0..512)
            .map(|_| {
                Boolean::new_witness(ark_relations::ns!(cs, "input bit"), || Ok(true)).unwrap()
            })
            .collect();
        evaluate_blake2s(&input_bits).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 21792);
    }

    #[test]
    fn test_blake2s_prf() {
        use crate::hash::prf::constraints::PRFGadget;

        let mut rng = ark_std::test_rng();
        let cs = ConstraintSystem::<Fr>::new_ref();

        let mut input = [0u8; 32];
        rng.fill(&mut input);

        let input_var =
            UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_input"), &input).unwrap();
        let out: [u8; 32] = {
            let mut h = Blake2s256::new();
            h.update(&input);
            h.finalize().into()
        };
        let actual_out_var = OutputVar(
            UInt8::new_witness_vec(ark_relations::ns!(cs, "declare_output"), &out).unwrap(),
        );

        let mut hasher = StatefulBlake2sGadget::default();
        hasher.update(&input_var).unwrap();
        let output_var = hasher.finalize().unwrap();
        output_var.enforce_equal(&actual_out_var).unwrap();

        if !cs.is_satisfied().unwrap() {
            println!(
                "which is unsatisfied: {:?}",
                cs.which_is_unsatisfied().unwrap()
            );
        }
        assert!(cs.is_satisfied().unwrap());
    }

    #[test]
    fn test_blake2s_precomp_constraints() {
        // Test that 512 fixed leading bits (constants)
        // doesn't result in more constraints.

        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = ark_std::test_rng();
        let input_bits: Vec<_> = (0..512)
            .map(|_| Boolean::constant(rng.gen()))
            .chain((0..512).map(|_| {
                Boolean::new_witness(ark_relations::ns!(cs, "input bit"), || Ok(true)).unwrap()
            }))
            .collect();
        evaluate_blake2s(&input_bits).unwrap();
        assert!(cs.is_satisfied().unwrap());
        assert_eq!(cs.num_constraints(), 21792);
    }

    #[test]
    fn test_blake2s_constant_constraints() {
        let cs = ConstraintSystem::<Fr>::new_ref();
        let mut rng = ark_std::test_rng();
        let input_bits: Vec<_> = (0..512)
            .map(|_| Boolean::<Fr>::constant(rng.gen()))
            .collect();
        evaluate_blake2s(&input_bits).unwrap();
        assert_eq!(cs.num_constraints(), 0);
    }

    #[test]
    fn test_blake2s() {
        let mut rng = ark_std::test_rng();

        for input_len in (0..32).chain((32..256).filter(|a| a % 8 == 0)) {
            let mut h = Blake2s256::new();

            let data: Vec<u8> = (0..input_len).map(|_| rng.gen()).collect();

            h.update(&data);

            let hash_result = h.finalize_fixed();

            let cs = ConstraintSystem::<Fr>::new_ref();

            let mut input_bits = vec![];

            for input_byte in data.into_iter() {
                for bit_i in 0..8 {
                    let cs = ark_relations::ns!(cs, "input bit");

                    input_bits.push(
                        Boolean::new_witness(cs, || Ok((input_byte >> bit_i) & 1u8 == 1u8))
                            .unwrap(),
                    );
                }
            }

            let r = evaluate_blake2s(&input_bits).unwrap();

            assert!(cs.is_satisfied().unwrap());

            let mut s = hash_result
                .iter()
                .flat_map(|&byte| (0..8).map(move |i| (byte >> i) & 1u8 == 1u8));

            for chunk in r {
                for b in chunk.to_bits_le().unwrap() {
                    assert_eq!(s.next().unwrap(), b.value().unwrap());
                }
            }
        }
    }
}
