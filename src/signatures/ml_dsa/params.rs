use crate::traits::MlDsaParams;

pub struct MlDsa44Params;
pub struct MlDsa65Params;
pub struct MlDsa87Params;

impl MlDsaParams<4, 4> for MlDsa44Params {
    const TAU: usize = 39;
    const LAMBDA: usize = 128;
    const GAMMA1: i32 = 1 << 17;
    const GAMMA2: i32 = (8380417 - 1) / 88;
    const ETA: i32 = 2;
    const BETA: i32 = 78;
    const OMEGA: usize = 80;

    type Seed = [u8; 32];
    type PrivateKey = [u8; 2560];
    type PublicKey = [u8; 1312];
    type Signature = [u8; 2420];
}

impl MlDsaParams<6, 5> for MlDsa65Params {
    const TAU: usize = 49;
    const LAMBDA: usize = 192;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (8380417 - 1) / 32;
    const ETA: i32 = 4;
    const BETA: i32 = 196;
    const OMEGA: usize = 55;

    type Seed = [u8; 32];
    type PrivateKey = [u8; 4032];
    type PublicKey = [u8; 1952];
    type Signature = [u8; 3309];
}

impl MlDsaParams<8, 7> for MlDsa87Params {
    const TAU: usize = 60;
    const LAMBDA: usize = 256;
    const GAMMA1: i32 = 1 << 19;
    const GAMMA2: i32 = (8380417 - 1) / 32;
    const ETA: i32 = 2;
    const BETA: i32 = 120;
    const OMEGA: usize = 75;

    type Seed = [u8; 32];
    type PrivateKey = [u8; 4896];
    type PublicKey = [u8; 2592];
    type Signature = [u8; 4627];
}
