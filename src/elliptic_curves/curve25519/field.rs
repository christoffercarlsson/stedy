use {
    crate::{
        traits::{ByteOrder, EdwardsParams, FieldElement},
        utils::Choice,
    },
    core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Neg, Sub, SubAssign},
};

#[cfg_attr(target_pointer_width = "32", path = "field32.rs")]
#[cfg_attr(target_pointer_width = "64", path = "field64.rs")]
mod field25519;

pub use field25519::Field25519;

impl Field25519 {
    const SQRT_M1: Self = Self::from_limbs([
        1718705420411056,
        234908883556509,
        2233514472574048,
        2117202627021982,
        765476049583133,
    ]);

    fn from_slice(slice: &[u8]) -> Self {
        let mut bytes = [0u8; 32];
        let size = slice.len().min(32);
        bytes[..size].copy_from_slice(&slice[..size]);
        Self::from(&bytes)
    }

    fn invert(self) -> Self {
        let x = self;
        let x3 = x * x.square();
        x3 * x.pow22523().pow2n(3)
    }

    fn pow22523(self) -> Self {
        let x = self;
        let x2 = x.square();
        let x4 = x2.square();
        let x8 = x4.square();
        let x9 = x * x8;
        let x11 = x2 * x9;
        let x22 = x11.square();
        let x31 = x9 * x22;
        let x10 = x31 * x31.pow2n(5);
        let x20 = x10 * x10.pow2n(10);
        let x40 = x20 * x20.pow2n(20);
        let x50 = x10 * x40.pow2n(10);
        let x100 = x50 * x50.pow2n(50);
        let x200 = x100 * x100.pow2n(100);
        let x250 = x50 * x200.pow2n(50);
        x * x250.pow2n(2)
    }

    fn pow2n(self, n: usize) -> Self {
        let mut x = self.square();
        for _ in 1..n {
            x = x.square();
        }
        x
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        let a = self;
        let b3 = b * b.square();
        let b7 = b * b3.square();
        let u = a * b3 * (a * b7).pow22523();
        let v = u * Self::SQRT_M1;
        let c = b * u.square();
        let d = b * v.square();
        let e = c.ct_eq(&a);
        let f = d.ct_eq(&a);
        let valid = e | f;
        let r = Self::select(&v, &u, e);
        let r = Self::select(&Self::ZERO, &r, valid);
        (r, valid)
    }
}

impl Add for Field25519 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

impl AddAssign for Field25519 {
    fn add_assign(&mut self, rhs: Self) {
        *self = self.add(rhs);
    }
}

impl Sub for Field25519 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.sub(rhs)
    }
}

impl SubAssign for Field25519 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = self.sub(rhs);
    }
}

impl Neg for Field25519 {
    type Output = Self;

    fn neg(self) -> Self::Output {
        self.neg()
    }
}

impl Mul for Field25519 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        self.mul(rhs)
    }
}

impl MulAssign for Field25519 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = self.mul(rhs);
    }
}

impl Div for Field25519 {
    type Output = Self;

    fn div(self, rhs: Self) -> Self::Output {
        self.mul(rhs.invert())
    }
}

impl DivAssign for Field25519 {
    fn div_assign(&mut self, rhs: Self) {
        *self = self.div(rhs);
    }
}

impl From<&[u8; 32]> for Field25519 {
    fn from(value: &[u8; 32]) -> Self {
        Self::from_bytes(value)
    }
}

impl From<[u8; 32]> for Field25519 {
    fn from(value: [u8; 32]) -> Self {
        Self::from(&value)
    }
}

impl From<&[u8]> for Field25519 {
    fn from(value: &[u8]) -> Self {
        Self::from_slice(value)
    }
}

impl From<u32> for Field25519 {
    fn from(value: u32) -> Self {
        Self::from_u32(value)
    }
}

impl From<Field25519> for [u8; 32] {
    fn from(value: Field25519) -> Self {
        value.to_bytes()
    }
}

impl From<&Field25519> for [u8; 32] {
    fn from(value: &Field25519) -> Self {
        Self::from(*value)
    }
}

impl FieldElement for Field25519 {
    const ZERO: Self = Self::ZERO;
    const ONE: Self = Self::ONE;

    const CAPACITY: usize = 254;
    const BYTE_ORDER: ByteOrder = ByteOrder::LittleEndian;

    type Bytes = [u8; 32];

    fn swap(a: &mut Self, b: &mut Self, condition: Choice) {
        Self::swap(a, b, condition);
    }

    fn select(a: &Self, b: &Self, condition: Choice) -> Self {
        Self::select(a, b, condition)
    }

    fn ct_eq(&self, other: &Self) -> Choice {
        self.ct_eq(other)
    }

    fn square(self) -> Self {
        self.square()
    }

    fn square2(self) -> Self {
        self.square2()
    }

    fn invert(self) -> Self {
        self.invert()
    }

    fn sqrt(self, b: Self) -> (Self, Choice) {
        self.sqrt(b)
    }
}

impl EdwardsParams<Field25519> for Field25519 {
    const D: Self = Self::from_limbs([
        929955233495203,
        466365720129213,
        1662059464998953,
        2033849074728123,
        1442794654840575,
    ]);
    const D2: Self = Self::from_limbs([
        1859910466990425,
        932731440258426,
        1072319116312658,
        1815898335770999,
        633789495995903,
    ]);
    const BASE_POINT_X: Self = Self::from_limbs([
        1738742601995546,
        1146398526822698,
        2070867633025821,
        562264141797630,
        587772402128613,
    ]);
    const BASE_POINT_Y: Self = Self::from_limbs([
        1801439850948184,
        1351079888211148,
        450359962737049,
        900719925474099,
        1801439850948198,
    ]);
    const BASE_POINT_T: Self = Self::from_limbs([
        1841354044333475,
        16398895984059,
        755974180946558,
        900171276175154,
        1821297809914039,
    ]);
    const BASE_COMB_LOW: [[Self; 3]; 8] = [
        [
            Self::from_limbs([
                2095828136623271,
                8345904203082,
                561934815651074,
                132866980779132,
                609687970313051,
            ]),
            Self::from_limbs([
                27061525496593,
                646507080609877,
                1691106538496974,
                984409644054134,
                189150386017206,
            ]),
            Self::from_limbs([
                2036362620803633,
                2055323031237507,
                1311177800343870,
                11939015390829,
                2090879950627211,
            ]),
        ],
        [
            Self::from_limbs([
                1780556929209962,
                2046154239336348,
                196480628783092,
                1255066305932916,
                1100727441785062,
            ]),
            Self::from_limbs([
                1934389912113823,
                1813910787783681,
                1182070337312237,
                945084394688198,
                820619882614965,
            ]),
            Self::from_limbs([
                1386514129792137,
                237525437624658,
                1106731187862656,
                1243117992780530,
                1182456632903256,
            ]),
        ],
        [
            Self::from_limbs([
                39077307831515,
                2239200459153156,
                1534849567934523,
                1044068948341378,
                1914976300556403,
            ]),
            Self::from_limbs([
                2100144914833040,
                1943167686978872,
                834544890649191,
                71152208886561,
                703349622011439,
            ]),
            Self::from_limbs([
                135982677252174,
                2067813794670100,
                1712580894344951,
                1055857319099517,
                502587050377322,
            ]),
        ],
        [
            Self::from_limbs([
                46650062604300,
                647211463603435,
                762005011162026,
                428712408171826,
                1681916835260511,
            ]),
            Self::from_limbs([
                1338752639845042,
                990353275471585,
                1247360220365633,
                1509597934129899,
                810849739557732,
            ]),
            Self::from_limbs([
                1181819698694540,
                363369611218239,
                542706119674435,
                662278782965930,
                1162972805315972,
            ]),
        ],
        [
            Self::from_limbs([
                792619782444500,
                1626341553318814,
                1590310496613608,
                1666079890813724,
                1305749908612973,
            ]),
            Self::from_limbs([
                970968901000144,
                1661575031223644,
                551956327884898,
                1769883887041227,
                1666557979832953,
            ]),
            Self::from_limbs([
                1036100142151195,
                1570148916922610,
                1764206086110509,
                327802643635198,
                478874167489351,
            ]),
        ],
        [
            Self::from_limbs([
                355511608754866,
                1848815508687954,
                284279953995098,
                131441822746186,
                257506559354133,
            ]),
            Self::from_limbs([
                1367520936978415,
                828087448929544,
                1181697318705726,
                743293205448062,
                1998377731804686,
            ]),
            Self::from_limbs([
                644456901702816,
                1895821712374659,
                182868156911320,
                1127043540230239,
                993195879110391,
            ]),
        ],
        [
            Self::from_limbs([
                324849554154832,
                1641011428731318,
                25629209260455,
                1142933917488058,
                858900514713899,
            ]),
            Self::from_limbs([
                1559175026950499,
                1277449990157729,
                1664855493895989,
                1973322385198905,
                721392410760226,
            ]),
            Self::from_limbs([
                1831002565915652,
                1076288187382578,
                2160772349364,
                643279622660722,
                2156621685398859,
            ]),
        ],
        [
            Self::from_limbs([
                18933040991961,
                738467196941269,
                2069529758246739,
                2136976083724305,
                962236734466435,
            ]),
            Self::from_limbs([
                549695558155633,
                1423962498507573,
                1854253303864821,
                502221547221120,
                671699837092871,
            ]),
            Self::from_limbs([
                1971659819471443,
                1266809808116152,
                1311407698082974,
                1012037327292909,
                514286959354680,
            ]),
        ],
    ];

    const BASE_COMB_HIGH: [[Self; 3]; 8] = [
        [
            Self::from_limbs([
                1954388595205244,
                446553453496772,
                1831264534299763,
                469467636255507,
                1783029159535678,
            ]),
            Self::from_limbs([
                467553834844123,
                265751223679856,
                344288747198917,
                2124319679258308,
                1166382626007490,
            ]),
            Self::from_limbs([
                1633529355585933,
                49089218284697,
                2013805181022795,
                1931852271731831,
                674494895586640,
            ]),
        ],
        [
            Self::from_limbs([
                1964007546594959,
                1420495111759559,
                975915877319868,
                932379363670541,
                576786742504052,
            ]),
            Self::from_limbs([
                1471751832882205,
                1371340513758414,
                1477330250317311,
                1346993068438066,
                147458000911689,
            ]),
            Self::from_limbs([
                794011475342670,
                943733438417333,
                1704194048330508,
                788029036023711,
                883233212245506,
            ]),
        ],
        [
            Self::from_limbs([
                1818438353766745,
                353889214384254,
                8361118849940,
                1775511074929380,
                1271688806917338,
            ]),
            Self::from_limbs([
                145149033686292,
                2136959898224902,
                2077415354485395,
                1770729899235455,
                788281428859807,
            ]),
            Self::from_limbs([
                1294279513587784,
                629704287258284,
                392868195201581,
                2159068075463223,
                920587171701617,
            ]),
        ],
        [
            Self::from_limbs([
                1099394178768470,
                1918166562354260,
                1989931156862428,
                1390626731873647,
                697624048324592,
            ]),
            Self::from_limbs([
                1187873695007256,
                585017905757107,
                1269763585303010,
                1871399018445801,
                16250281427499,
            ]),
            Self::from_limbs([
                1715807746088249,
                588173483944335,
                207817266940586,
                1638337651989331,
                756014777080980,
            ]),
        ],
        [
            Self::from_limbs([
                1052691664329658,
                1499019535780725,
                325690362405592,
                456834102161349,
                2179607795653517,
            ]),
            Self::from_limbs([
                938472001336443,
                2069703776423548,
                1361520028869214,
                1013656445643637,
                1747558040207143,
            ]),
            Self::from_limbs([
                753895153807990,
                622760158425131,
                290922996251912,
                308093504461728,
                858168839440009,
            ]),
        ],
        [
            Self::from_limbs([
                1128531045542587,
                935687113003863,
                1662703181200270,
                96491932066422,
                2064367866062544,
            ]),
            Self::from_limbs([
                1929183913469825,
                265915291502907,
                1620999925620350,
                534509860521058,
                371869451838099,
            ]),
            Self::from_limbs([
                1791105019894840,
                203970369546263,
                404184330693670,
                710692036252715,
                2145453898609371,
            ]),
        ],
        [
            Self::from_limbs([
                338829141723677,
                2239027954263625,
                2209768841530960,
                1143703266995742,
                1380381800552974,
            ]),
            Self::from_limbs([
                985275822782547,
                517930874909712,
                646291702595699,
                1545043111195253,
                1324836791505453,
            ]),
            Self::from_limbs([
                1080258570284283,
                811656117101489,
                768201012093140,
                2131407412142031,
                292548462084586,
            ]),
        ],
        [
            Self::from_limbs([
                157208445823196,
                2142831237006543,
                141404410183475,
                606426804891989,
                1375680890971601,
            ]),
            Self::from_limbs([
                995184023886672,
                954294014172563,
                198349948314311,
                1332834396048020,
                472954343610170,
            ]),
            Self::from_limbs([
                967258038805556,
                1150034054218028,
                1766961884569720,
                93901147686063,
                1870310514087056,
            ]),
        ],
    ];
}
