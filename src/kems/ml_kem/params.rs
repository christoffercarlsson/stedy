use crate::traits::MlKemParams;

pub struct MlKem512Params;
pub struct MlKem768Params;
pub struct MlKem1024Params;

impl MlKemParams<2> for MlKem512Params {
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 1632];
    type PublicKey = [u8; 800];
    type Ciphertext = [u8; 768];
}

impl MlKemParams<3> for MlKem768Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 2400];
    type PublicKey = [u8; 1184];
    type Ciphertext = [u8; 1088];
}

impl MlKemParams<4> for MlKem1024Params {
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;

    type Seed = [u8; 64];
    type SharedSecret = [u8; 32];
    type PrivateKey = [u8; 3168];
    type PublicKey = [u8; 1568];
    type Ciphertext = [u8; 1568];
}
