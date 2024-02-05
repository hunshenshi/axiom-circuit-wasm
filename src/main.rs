mod circuit;

use axiom_wasm::{prepare_prove, run_prove};
use circuit::example::{some_algorithm_in_zk, CircuitInput};

fn main() {
    let private_inputs: CircuitInput = serde_json::from_str(
        "{
        \"x\": \"12\"
    }",
    )
    .unwrap();
    let (params, pk, c_params, break_points) =
        prepare_prove(some_algorithm_in_zk, private_inputs.clone());
    run_prove(
        some_algorithm_in_zk,
        private_inputs,
        params,
        pk,
        c_params,
        break_points,
    );
}