use ark_crypto_primitives::crh::{injective_map::{PedersenCRHCompressor, TECompressor}, pedersen};
use ark_crypto_primitives::crh::constraints::{CRHGadget, TwoToOneCRHGadget};
use ark_crypto_primitives::crh::injective_map::constraints::{
    PedersenCRHCompressorGadget, TECompressorGadget,
};
use ark_ed_on_bls12_381::{constraints::EdwardsVar, EdwardsProjective};

// Pedersen hash with two input
pub type TwoToOneHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, TwoToOneWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct TwoToOneWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing two outputs.
impl pedersen::Window for TwoToOneWindow {
    const WINDOW_SIZE: usize = 2;
    const NUM_WINDOWS: usize = 256;
}

// pedersen Hash with single input
pub type LeafHash = PedersenCRHCompressor<EdwardsProjective, TECompressor, LeafWindow>;

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct LeafWindow;

// `WINDOW_SIZE * NUM_WINDOWS` = 2 * 256 bits = enough for hashing single input.
impl pedersen::Window for LeafWindow {
    const WINDOW_SIZE: usize = 4;
    const NUM_WINDOWS: usize = 256;
}

//Zksnark gadget for pedersen hash with two input
pub type TwoToOneHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    TwoToOneWindow,
    EdwardsVar,
    TECompressorGadget,
>;

//Zksnark gadget for pedersen hash with single input
pub type LeafHashGadget = PedersenCRHCompressorGadget<
    EdwardsProjective,
    TECompressor,
    LeafWindow,
    EdwardsVar,
    TECompressorGadget,
>;

// working curve
pub type ConstraintF = ark_ed_on_bls12_381::Fq;

//hash generator setup for leaf hash
pub type LeafHashParamsVar = <LeafHashGadget as CRHGadget<LeafHash, ConstraintF>>::ParametersVar;

//hash generator setup for internal node hash
pub type TwoToOneHashParamsVar =
<TwoToOneHashGadget as TwoToOneCRHGadget<TwoToOneHash, ConstraintF>>::ParametersVar;


