use std::{env::var, time::Instant};

use circuit::example::{some_algorithm_in_zk, CircuitInput};
use halo2_base::{gates::{circuit::{builder::BaseCircuitBuilder, BaseCircuitParams, CircuitBuilderStage}, flex_gate::MultiPhaseThreadBreakPoints}, halo2_proofs::{halo2curves::bn256::{Bn256, Fr, G1Affine}, plonk::{Circuit, ProvingKey}, poly::{commitment::Params, kzg::commitment::ParamsKZG}}, utils::fs::gen_srs, AssignedValue};
use serde::de::DeserializeOwned;
use snark_verifier_sdk::{gen_pk, halo2::gen_snark_shplonk, Snark};
use wasm_bindgen::prelude::wasm_bindgen;

mod circuit;

pub struct CircuitScaffold<T, Fn> {
    pub f: Fn,
    pub private_inputs: T,
}

impl<T, Fn> CircuitScaffold<T, Fn>
where
    Fn: FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
{
    /// Creates a Halo2 circuit from the given function.
    pub fn create_circuit(
        self,
        stage: CircuitBuilderStage,
        pinning: Option<(BaseCircuitParams, MultiPhaseThreadBreakPoints)>,
        params: &ParamsKZG<Bn256>,
    ) -> BaseCircuitBuilder<Fr> {
        let mut builder = BaseCircuitBuilder::from_stage(stage);
        if let Some((params, break_points)) = pinning {
            builder.set_params(params);
            builder.set_break_points(break_points);
        } else {
            let k = params.k() as usize;
            // we use env var `LOOKUP_BITS` to determine whether to use `GateThreadBuilder` or `RangeCircuitBuilder`. The difference is that the latter creates a lookup table with 2^LOOKUP_BITS rows, while the former does not.
            let lookup_bits: Option<usize> = var("LOOKUP_BITS")
                .map(|str| {
                    let lookup_bits = str.parse::<usize>().unwrap();
                    // we use a lookup table with 2^LOOKUP_BITS rows. Due to blinding factors, we need a little more than 2^LOOKUP_BITS rows total in our circuit
                    assert!(lookup_bits < k, "LOOKUP_BITS needs to be less than DEGREE");
                    lookup_bits
                })
                .ok();
            // we initiate a "thread builder". This is what keeps track of the execution trace of our program. If not in proving mode, it also keeps track of the ZK constraints.
            builder.set_k(k);
            if let Some(lookup_bits) = lookup_bits {
                builder.set_lookup_bits(lookup_bits);
            }
            builder.set_instance_columns(1);
        };

        // builder.main(phase) gets a default "main" thread for the given phase. For most purposes we only need to think about phase 0
        // we need a 64-bit number as input in this case
        // while `some_algorithm_in_zk` was written generically for any field `F`, in practice we use the scalar field of the BN254 curve because that's what the proving system backend uses
        let mut assigned_instances = vec![];
        (self.f)(&mut builder, self.private_inputs, &mut assigned_instances);
        if !assigned_instances.is_empty() {
            assert_eq!(builder.assigned_instances.len(), 1, "num_instance_columns != 1");
            builder.assigned_instances[0] = assigned_instances;
        }

        if !stage.witness_gen_only() {
            // now `builder` contains the execution trace, and we are ready to actually create the circuit
            // minimum rows is the number of rows used for blinding factors. This depends on the circuit itself, but we can guess the number and change it if something breaks (default 9 usually works)
            let minimum_rows =
                var("MINIMUM_ROWS").unwrap_or_else(|_| "20".to_string()).parse().unwrap();
            builder.calculate_params(Some(minimum_rows));
        }

        builder
    }
}

pub fn prepare_prove<T: DeserializeOwned>(
    f: impl FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
) -> (
    ParamsKZG<Bn256>,
    ProvingKey<G1Affine>,
    BaseCircuitParams,
    MultiPhaseThreadBreakPoints,
) {
    let k = 10;
    let params = gen_srs(k);
    println!("Universal trusted setup (unsafe!) available at: params/kzg_bn254_{k}.srs");

    let precircuit = CircuitScaffold { f, private_inputs };
    let circuit = precircuit.create_circuit(CircuitBuilderStage::Keygen, None, &params);
    let pk = gen_pk(&params, &circuit, None);
    let c_params = circuit.params();
    let break_points = circuit.break_points();
    (params, pk, c_params, break_points)
}

pub fn run_prove<T: DeserializeOwned>(
    f: impl FnOnce(&mut BaseCircuitBuilder<Fr>, T, &mut Vec<AssignedValue<Fr>>),
    private_inputs: T,
    params: ParamsKZG<Bn256>,
    pk: ProvingKey<G1Affine>,
    c_params: BaseCircuitParams,
    break_points: MultiPhaseThreadBreakPoints,
) -> Snark {
    let pinning: (BaseCircuitParams, MultiPhaseThreadBreakPoints) = (c_params, break_points);
    let precircuit = CircuitScaffold { f, private_inputs };
    let circuit = precircuit.create_circuit(CircuitBuilderStage::Prover, Some(pinning), &params);

    let start = Instant::now();
    let snark = gen_snark_shplonk(&params, &pk, circuit, None::<&str>);
    let prover_time = start.elapsed();
    println!("Proving time: {:?}", prover_time);
    println!("{:?}", snark);
    snark
}

#[wasm_bindgen]
pub fn prove(input: &str) -> std::string::String {
    let private_inputs: CircuitInput = serde_json::from_str(&input).unwrap();
    let (params, pk, c_params, break_points) =
        prepare_prove(some_algorithm_in_zk, private_inputs.clone());
    let snark = run_prove(
        some_algorithm_in_zk,
        private_inputs,
        params,
        pk,
        c_params,
        break_points,
    );
    format!(
        r#"{}"#,
        hex::encode(serde_json::to_string(&snark).unwrap()),
    )
}