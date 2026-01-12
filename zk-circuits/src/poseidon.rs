use halo2_proofs::{
    arithmetic::Field,
    circuit::{AssignedCell, Chip, Layouter, Region, SimpleFloorPlanner, Value},
    plonk::{Advice, Circuit, Column, ConstraintSystem, Error, Expression, Fixed, Selector},
    poly::Rotation,
};
use halo2curves::bn256::Fr as Fp;
use std::marker::PhantomData;

pub const POSEIDON_WIDTH: usize = 3;
pub const POSEIDON_RATE: usize = 2;
pub const POSEIDON_ROUNDS_F: usize = 8;
pub const POSEIDON_ROUNDS_P: usize = 57;

pub const ROUND_CONSTANTS: [[u64; POSEIDON_WIDTH]; POSEIDON_ROUNDS_F + POSEIDON_ROUNDS_P] = {
    let mut constants = [[0u64; POSEIDON_WIDTH]; POSEIDON_ROUNDS_F + POSEIDON_ROUNDS_P];
    let mut i = 0;
    while i < POSEIDON_ROUNDS_F + POSEIDON_ROUNDS_P {
        constants[i] = [
            (i * 3 + 1) as u64 * 0x1234567890abcdef,
            (i * 3 + 2) as u64 * 0xfedcba0987654321,
            (i * 3 + 3) as u64 * 0x0f1e2d3c4b5a6978,
        ];
        i += 1;
    }
    constants
};

pub const MDS_MATRIX: [[u64; POSEIDON_WIDTH]; POSEIDON_WIDTH] = [
    [2, 1, 1],
    [1, 2, 1],
    [1, 1, 2],
];

#[derive(Clone, Debug)]
pub struct PoseidonSpec;

#[derive(Clone, Debug)]
pub struct PoseidonConfig {
    pub state: [Column<Advice>; POSEIDON_WIDTH],
    pub round_constants: [Column<Fixed>; POSEIDON_WIDTH],
    pub selector_full: Selector,
    pub selector_partial: Selector,
}

pub struct PoseidonChip<F: Field> {
    config: PoseidonConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> Chip<F> for PoseidonChip<F> {
    type Config = PoseidonConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: Field> PoseidonChip<F> {
    pub fn construct(config: PoseidonConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        state: [Column<Advice>; POSEIDON_WIDTH],
        round_constants: [Column<Fixed>; POSEIDON_WIDTH],
    ) -> PoseidonConfig {
        let selector_full = meta.selector();
        let selector_partial = meta.selector();

        for col in state.iter() {
            meta.enable_equality(*col);
        }

        meta.create_gate("poseidon_full_round", |meta| {
            let s = meta.query_selector(selector_full);
            let state_cur: Vec<_> = state.iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect();
            let state_next: Vec<_> = state.iter()
                .map(|c| meta.query_advice(*c, Rotation::next()))
                .collect();
            let rc: Vec<_> = round_constants.iter()
                .map(|c| meta.query_fixed(*c, Rotation::cur()))
                .collect();

            let mut constraints = Vec::new();
            for i in 0..POSEIDON_WIDTH {
                let sbox_input = state_cur[i].clone() + rc[i].clone();
                let sbox_output = sbox_input.clone() * sbox_input.clone() * sbox_input.clone() 
                    * sbox_input.clone() * sbox_input.clone();
                
                let mut mix = Expression::Constant(F::ZERO);
                for j in 0..POSEIDON_WIDTH {
                    let mds_entry = Expression::Constant(F::from(MDS_MATRIX[i][j]));
                    let sbox_j = {
                        let input_j = state_cur[j].clone() + rc[j].clone();
                        input_j.clone() * input_j.clone() * input_j.clone() 
                            * input_j.clone() * input_j.clone()
                    };
                    mix = mix + mds_entry * sbox_j;
                }
                
                constraints.push(s.clone() * (state_next[i].clone() - mix));
            }
            constraints
        });

        meta.create_gate("poseidon_partial_round", |meta| {
            let s = meta.query_selector(selector_partial);
            let state_cur: Vec<_> = state.iter()
                .map(|c| meta.query_advice(*c, Rotation::cur()))
                .collect();
            let state_next: Vec<_> = state.iter()
                .map(|c| meta.query_advice(*c, Rotation::next()))
                .collect();
            let rc: Vec<_> = round_constants.iter()
                .map(|c| meta.query_fixed(*c, Rotation::cur()))
                .collect();

            let mut constraints = Vec::new();
            
            let sbox0_input = state_cur[0].clone() + rc[0].clone();
            let sbox0_output = sbox0_input.clone() * sbox0_input.clone() * sbox0_input.clone()
                * sbox0_input.clone() * sbox0_input.clone();
            
            for i in 0..POSEIDON_WIDTH {
                let mds_entry_0 = Expression::Constant(F::from(MDS_MATRIX[i][0]));
                let mut mix = mds_entry_0 * sbox0_output.clone();
                
                for j in 1..POSEIDON_WIDTH {
                    let mds_entry = Expression::Constant(F::from(MDS_MATRIX[i][j]));
                    mix = mix + mds_entry * (state_cur[j].clone() + rc[j].clone());
                }
                
                constraints.push(s.clone() * (state_next[i].clone() - mix));
            }
            constraints
        });

        PoseidonConfig {
            state,
            round_constants,
            selector_full,
            selector_partial,
        }
    }

    pub fn hash(
        &self,
        mut layouter: impl Layouter<F>,
        inputs: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "poseidon hash",
            |mut region| {
                self.hash_inner(&mut region, inputs)
            },
        )
    }

    fn hash_inner(
        &self,
        region: &mut Region<'_, F>,
        inputs: &[AssignedCell<F, F>],
    ) -> Result<AssignedCell<F, F>, Error> {
        let mut state: Vec<Value<F>> = vec![Value::known(F::ZERO); POSEIDON_WIDTH];
        
        for (i, input) in inputs.iter().enumerate() {
            if i < POSEIDON_RATE {
                state[i] = input.value().copied();
            }
        }

        let total_rounds = POSEIDON_ROUNDS_F + POSEIDON_ROUNDS_P;
        let half_full = POSEIDON_ROUNDS_F / 2;

        for round in 0..total_rounds {
            let is_full_round = round < half_full || round >= half_full + POSEIDON_ROUNDS_P;
            
            if is_full_round {
                self.config.selector_full.enable(region, round)?;
            } else {
                self.config.selector_partial.enable(region, round)?;
            }

            for (i, col) in self.config.round_constants.iter().enumerate() {
                region.assign_fixed(
                    || format!("rc_{}_{}", round, i),
                    *col,
                    round,
                    || Value::known(F::from(ROUND_CONSTANTS[round][i])),
                )?;
            }

            for (i, col) in self.config.state.iter().enumerate() {
                region.assign_advice(
                    || format!("state_{}_{}", round, i),
                    *col,
                    round,
                    || state[i],
                )?;
            }

            state = self.permute_round(&state, round, is_full_round);
        }

        let output = region.assign_advice(
            || "output",
            self.config.state[0],
            total_rounds,
            || state[0],
        )?;

        Ok(output)
    }

    fn permute_round(&self, state: &[Value<F>], round: usize, is_full: bool) -> Vec<Value<F>> {
        let rc: Vec<F> = ROUND_CONSTANTS[round]
            .iter()
            .map(|&x| F::from(x))
            .collect();

        let sboxed: Vec<Value<F>> = if is_full {
            state.iter().zip(rc.iter())
                .map(|(s, r)| {
                    s.map(|v| {
                        let t = v + *r;
                        t * t * t * t * t
                    })
                })
                .collect()
        } else {
            let mut result = state.to_vec();
            result[0] = state[0].map(|v| {
                let t = v + rc[0];
                t * t * t * t * t
            });
            for (i, r) in rc.iter().enumerate().skip(1) {
                result[i] = state[i].map(|v| v + *r);
            }
            result
        };

        let mut mixed = vec![Value::known(F::ZERO); POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                let mds = F::from(MDS_MATRIX[i][j]);
                mixed[i] = mixed[i] + sboxed[j].map(|v| v * mds);
            }
        }
        mixed
    }
}

pub fn poseidon_hash_native(inputs: &[Fp]) -> Fp {
    let mut state = [Fp::ZERO; POSEIDON_WIDTH];
    
    for (i, input) in inputs.iter().enumerate() {
        if i < POSEIDON_RATE {
            state[i] = *input;
        }
    }

    let total_rounds = POSEIDON_ROUNDS_F + POSEIDON_ROUNDS_P;
    let half_full = POSEIDON_ROUNDS_F / 2;

    for round in 0..total_rounds {
        let is_full = round < half_full || round >= half_full + POSEIDON_ROUNDS_P;
        
        for i in 0..POSEIDON_WIDTH {
            state[i] += Fp::from(ROUND_CONSTANTS[round][i]);
        }

        if is_full {
            for i in 0..POSEIDON_WIDTH {
                state[i] = state[i] * state[i] * state[i] * state[i] * state[i];
            }
        } else {
            state[0] = state[0] * state[0] * state[0] * state[0] * state[0];
        }

        let mut new_state = [Fp::ZERO; POSEIDON_WIDTH];
        for i in 0..POSEIDON_WIDTH {
            for j in 0..POSEIDON_WIDTH {
                new_state[i] += Fp::from(MDS_MATRIX[i][j]) * state[j];
            }
        }
        state = new_state;
    }

    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_poseidon_native() {
        let inputs = [Fp::from(1u64), Fp::from(2u64)];
        let hash = poseidon_hash_native(&inputs);
        assert_ne!(hash, Fp::ZERO);
        
        let hash2 = poseidon_hash_native(&inputs);
        assert_eq!(hash, hash2);
        
        let inputs2 = [Fp::from(1u64), Fp::from(3u64)];
        let hash3 = poseidon_hash_native(&inputs2);
        assert_ne!(hash, hash3);
    }
}
