use crate::traits::MontgomeryParams;

#[cfg_attr(target_pointer_width = "32", path = "montgomery/montgomery32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "montgomery/montgomery64.rs")]
mod monty;

pub use monty::Montgomery;

impl<const LIMBS: usize, P> Montgomery<LIMBS, P>
where
    P: MontgomeryParams<LIMBS>,
{
    pub(crate) fn select(a: &Self, b: &Self, condition: u64) -> Self {
        let mut x = *a;
        let mut y = *b;
        Self::swap(&mut x, &mut y, condition);
        x
    }
}
