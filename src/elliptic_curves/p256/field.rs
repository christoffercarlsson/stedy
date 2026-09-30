use {
    crate::{
        traits::{ByteOrder, FieldElement, MontgomeryParams, WeierstrassParams},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field_p256;

pub use field_p256::FieldP256;

#[derive(Clone, Copy)]
pub struct FieldP256Params;

impl MontgomeryParams<4> for FieldP256Params {
    const MOD: [u64; 4] = [18446744073709551615, 4294967295, 0, 18446744069414584321];
    const ONE: [u64; 4] = [1, 18446744069414584320, 18446744073709551615, 4294967294];
    const R2: [u64; 4] = [3, 18446744056529682431, 18446744073709551614, 21474836477];
    const N0: u64 = 1;
}

impl FieldP256 {
    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    #[cfg(target_pointer_width = "64")]
    fn invert(self) -> Self {
        let x = self;
        x * x.pow_p_minus_3_div_4().pow2n(2)
    }

    #[cfg(target_pointer_width = "32")]
    fn invert(self) -> Self {
        self.invert_binary()
    }

    fn pow_p_minus_3_div_4(self) -> Self {
        let x = self;
        let f2 = x * x.square();
        let f4 = f2 * f2.pow2n(2);
        let f8 = f4 * f4.pow2n(4);
        let f16 = f8 * f8.pow2n(8);
        let f32 = f16 * f16.pow2n(16);
        let f64 = f32 * f32.pow2n(32);
        let f24 = f8 * f16.pow2n(8);
        let f28 = f4 * f24.pow2n(4);
        let f30 = f2 * f28.pow2n(2);
        let f94 = f30 * f64.pow2n(30);
        let acc = x * f32.pow2n(32);
        let acc = acc.pow2n(96);
        f94 * acc.pow2n(94)
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let u = self;
        let v = b;
        let v2 = v.square();
        let v3 = v2 * v;
        let r = u * v * (u * v3).pow_p_minus_3_div_4();
        let c = v * r.square();
        let valid = u.ct_eq(&c);
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
}

impl Add for FieldP256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for FieldP256 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for FieldP256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for FieldP256 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for FieldP256 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for FieldP256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for FieldP256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Div for FieldP256 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for FieldP256 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl From<&[u8; 32]> for FieldP256 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_be_bytes(value)
    }
}

impl From<[u8; 32]> for FieldP256 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for FieldP256 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for FieldP256 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<FieldP256> for [u8; 32] {
    fn from(value: FieldP256) -> Self {
        value.to_be_bytes()
    }
}

impl From<&FieldP256> for [u8; 32] {
    fn from(value: &FieldP256) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for FieldP256 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 255;
    const BYTE_ORDER: ByteOrder = ByteOrder::BigEndian;

    type Bytes = [u8; 32];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
    }

    fn assign(&mut self, other: &Self, condition: Choice) {
        self.assign(other, condition);
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        self.sqrt(b)
    }
}

impl WeierstrassParams<FieldP256> for FieldP256 {
    const A: FieldP256 =
        FieldP256::from_limbs([18446744073709551612, 17179869183, 0, 18446744056529682436]);
    const B: FieldP256 = FieldP256::from_limbs([
        15608596021259845087,
        12461466548982526096,
        16546823903870267094,
        15866188208926050356,
    ]);
    const BASE_POINT_X: FieldP256 = FieldP256::from_limbs([
        8784043285714375740,
        8483257759279461889,
        8789745728267363600,
        1770019616739251654,
    ]);
    const BASE_POINT_Y: FieldP256 = FieldP256::from_limbs([
        15992936863339206154,
        10037038012062884956,
        15197544864945402661,
        9615747158586711429,
    ]);
    const BASE_NAF: [[FieldP256; 2]; 8] = [
        [
            FieldP256::from_limbs([
                8784043285714375740,
                8483257759279461889,
                8789745728267363600,
                1770019616739251654,
            ]),
            FieldP256::from_limbs([
                15992936863339206154,
                10037038012062884956,
                15197544864945402661,
                9615747158586711429,
            ]),
        ],
        [
            FieldP256::from_limbs([
                18423170064697770279,
                12693387071620743675,
                7398701556189346968,
                2779682216903406718,
            ]),
            FieldP256::from_limbs([
                12703629940499916779,
                6358598532389273114,
                8683512038509439374,
                15415938252666293255,
            ]),
        ],
        [
            FieldP256::from_limbs([
                13698695174800826869,
                10442832251048252285,
                10672604962207744524,
                14485711676978308040,
            ]),
            FieldP256::from_limbs([
                16947216143812808464,
                8342189264337602603,
                3837253281927274344,
                8331789856935110934,
            ]),
        ],
        [
            FieldP256::from_limbs([
                524165018444839759,
                3157588572894920951,
                17599692088379947784,
                1421537803477597699,
            ]),
            FieldP256::from_limbs([
                2902517390503550285,
                7440776657136679901,
                17263207614729765269,
                16928425260420958311,
            ]),
        ],
        [
            FieldP256::from_limbs([
                8487436533858443496,
                12386798851261442113,
                3224748875345095424,
                16166568617729909099,
            ]),
            FieldP256::from_limbs([
                2213369110503306004,
                6246347469485852131,
                3129440554298978074,
                605269941184323483,
            ]),
        ],
        [
            FieldP256::from_limbs([
                16896703203004244996,
                11377226897030111200,
                2302364246994590389,
                4499255394192625779,
            ]),
            FieldP256::from_limbs([
                1906858144627445384,
                2670515414718439880,
                868537809054295101,
                7535366755622172814,
            ]),
        ],
        [
            FieldP256::from_limbs([
                14754959387565938441,
                1023838193204581133,
                13599978343236540433,
                8323909593307920217,
            ]),
            FieldP256::from_limbs([
                3852032956982813055,
                7526785533690696419,
                8993798556223495105,
                18140648187477079959,
            ]),
        ],
        [
            FieldP256::from_limbs([
                8267721299596412251,
                273633183929630283,
                17164190306640434032,
                16332882679719778825,
            ]),
            FieldP256::from_limbs([
                4663567915067622493,
                15521151801790569253,
                7273215397645141911,
                2324445691280731636,
            ]),
        ],
    ];
    const BASE_COMB_LOW: [[FieldP256; 2]; 8] = [
        [
            FieldP256::from_limbs([
                16276378303213485519,
                11610642555549009998,
                12968549917711219144,
                13614032081606875767,
            ]),
            FieldP256::from_limbs([
                14468637405998134218,
                16946104577738048249,
                5796269081330592996,
                13155830452195217551,
            ]),
        ],
        [
            FieldP256::from_limbs([
                10960106239292906373,
                16809609806924566483,
                13031612020741193020,
                13291345741750077342,
            ]),
            FieldP256::from_limbs([
                7954734005167757873,
                17383850464052107445,
                12931708472233919352,
                3300046774153275471,
            ]),
        ],
        [
            FieldP256::from_limbs([
                16941532255742388747,
                8346751492207936928,
                7375050649627231252,
                17274378087627363391,
            ]),
            FieldP256::from_limbs([
                2614661496042926000,
                9583062708795066448,
                14633664087210645439,
                17346147384975052897,
            ]),
        ],
        [
            FieldP256::from_limbs([
                2213430789879392913,
                15879210110311748830,
                5674567682534312105,
                282127179730440278,
            ]),
            FieldP256::from_limbs([
                15997535019390205053,
                16193064887603680119,
                10659746731033454998,
                6803983463739157485,
            ]),
        ],
        [
            FieldP256::from_limbs([
                879963065398216846,
                2973476574486802070,
                8843367792183029089,
                5650326532681232023,
            ]),
            FieldP256::from_limbs([
                127964786672840674,
                2754561636337218835,
                6277103883835147899,
                114163733589667367,
            ]),
        ],
        [
            FieldP256::from_limbs([
                12746512913719710359,
                14820310095988272345,
                3764032979627938494,
                5195269264094837944,
            ]),
            FieldP256::from_limbs([
                2630102451020065704,
                15741745314828424324,
                15443524967567106910,
                10622922286051161181,
            ]),
        ],
        [
            FieldP256::from_limbs([
                17673108769487588684,
                15104691168448070740,
                3221106148829084350,
                10081166234651067486,
            ]),
            FieldP256::from_limbs([
                507356821577171918,
                9696598831169311175,
                18252058791079509006,
                16021857620055149217,
            ]),
        ],
        [
            FieldP256::from_limbs([
                7239755105411399118,
                3184767757947337190,
                5660301761056761825,
                16192326037872361995,
            ]),
            FieldP256::from_limbs([
                950591516902882135,
                1921926390145105927,
                17943245458769692996,
                8196590758835664756,
            ]),
        ],
    ];
    const BASE_COMB_HIGH: [[FieldP256; 2]; 8] = [
        [
            FieldP256::from_limbs([
                13972395204066918999,
                17813195925452250905,
                2485744254807281578,
                12200221907272164891,
            ]),
            FieldP256::from_limbs([
                11495738808819338137,
                8416998531833569014,
                6745930105261127250,
                14291433097740138678,
            ]),
        ],
        [
            FieldP256::from_limbs([
                9644170934695573499,
                1279450795419508427,
                534623249335280685,
                323202124490813286,
            ]),
            FieldP256::from_limbs([
                9930445905712134703,
                1772439765092192846,
                12916777188848840125,
                17070600319053444754,
            ]),
        ],
        [
            FieldP256::from_limbs([
                8505799075819708741,
                11582628558648954287,
                4669851519007969401,
                4887074672290645358,
            ]),
            FieldP256::from_limbs([
                2612212302890301820,
                16607633265888877601,
                12778811196442130008,
                688829259585743965,
            ]),
        ],
        [
            FieldP256::from_limbs([
                16092347001048359480,
                17458728397797944972,
                3104685174317499034,
                14396672446409662943,
            ]),
            FieldP256::from_limbs([
                2493196000060584371,
                15759898003805709639,
                1148497723184462155,
                9460100144395811867,
            ]),
        ],
        [
            FieldP256::from_limbs([
                14174634148053357879,
                6458863300788989574,
                15340361638531024867,
                6423617982534376600,
            ]),
            FieldP256::from_limbs([
                15746435079786566457,
                4265662040479161208,
                10135794956075496944,
                14923149270245375957,
            ]),
        ],
        [
            FieldP256::from_limbs([
                15624602322174404118,
                13120877476619777321,
                12626256666615747198,
                6583929281724094464,
            ]),
            FieldP256::from_limbs([
                16115822379308113023,
                2731533629445046089,
                16173620025041590144,
                13838834552267480651,
            ]),
        ],
        [
            FieldP256::from_limbs([
                5493301155682600020,
                12372756626858229857,
                8776668246700576646,
                3674280120874611585,
            ]),
            FieldP256::from_limbs([
                16017337314196405892,
                12334102274300871286,
                13162556539041366579,
                12879888362878923514,
            ]),
        ],
        [
            FieldP256::from_limbs([
                14529135825762684915,
                1508662083300291631,
                7422336242683183599,
                1455438706906951318,
            ]),
            FieldP256::from_limbs([
                17034944933350489126,
                11984052714196021875,
                16395907385768480602,
                14622985728700240582,
            ]),
        ],
    ];

    type PointBytes = [u8; 33];
}
