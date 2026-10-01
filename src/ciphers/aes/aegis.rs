macro_rules! impl_aegis {
    () => {
        const C0: [u8; 16] = [0, 1, 1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144, 233, 121, 98];
        const C1: [u8; 16] = [
            219, 61, 24, 85, 109, 194, 47, 241, 32, 17, 49, 66, 115, 181, 40, 221,
        ];

        #[target_feature(enable = "aes")]
        pub(super) fn aegis128l_encrypt<const TAG_SIZE: usize>(
            key: &[u8; 16],
            nonce: &[u8; 16],
            aad: &[u8],
            data: &mut [u8],
        ) -> [u8; TAG_SIZE] {
            let mut state = aegis128l_init(key, nonce);
            aegis128l_absorb(&mut state, aad);
            let (blocks, remainder) = data.as_chunks_mut::<32>();
            for block in blocks {
                aegis128l_encrypt_block(&mut state, block);
            }
            if !remainder.is_empty() {
                let mut block = [0u8; 32];
                block[..remainder.len()].copy_from_slice(remainder);
                aegis128l_encrypt_block(&mut state, &mut block);
                remainder.copy_from_slice(&block[..remainder.len()]);
            }
            aegis128l_finalize::<TAG_SIZE>(&mut state, aad.len(), data.len())
        }

        #[target_feature(enable = "aes")]
        pub(super) fn aegis128l_decrypt<const TAG_SIZE: usize>(
            key: &[u8; 16],
            nonce: &[u8; 16],
            aad: &[u8],
            data: &mut [u8],
        ) -> [u8; TAG_SIZE] {
            let mut state = aegis128l_init(key, nonce);
            aegis128l_absorb(&mut state, aad);
            let (blocks, remainder) = data.as_chunks_mut::<32>();
            for block in blocks {
                aegis128l_decrypt_block(&mut state, block);
            }
            if !remainder.is_empty() {
                aegis128l_decrypt_partial(&mut state, remainder);
            }
            aegis128l_finalize::<TAG_SIZE>(&mut state, aad.len(), data.len())
        }

        #[target_feature(enable = "aes")]
        pub(super) fn aegis256_encrypt<const TAG_SIZE: usize>(
            key: &[u8; 32],
            nonce: &[u8; 32],
            aad: &[u8],
            data: &mut [u8],
        ) -> [u8; TAG_SIZE] {
            let mut state = aegis256_init(key, nonce);
            aegis256_absorb(&mut state, aad);
            let (blocks, remainder) = data.as_chunks_mut::<16>();
            for block in blocks {
                aegis256_encrypt_block(&mut state, block);
            }
            if !remainder.is_empty() {
                let mut block = [0u8; 16];
                block[..remainder.len()].copy_from_slice(remainder);
                aegis256_encrypt_block(&mut state, &mut block);
                remainder.copy_from_slice(&block[..remainder.len()]);
            }
            aegis256_finalize::<TAG_SIZE>(&mut state, aad.len(), data.len())
        }

        #[target_feature(enable = "aes")]
        pub(super) fn aegis256_decrypt<const TAG_SIZE: usize>(
            key: &[u8; 32],
            nonce: &[u8; 32],
            aad: &[u8],
            data: &mut [u8],
        ) -> [u8; TAG_SIZE] {
            let mut state = aegis256_init(key, nonce);
            aegis256_absorb(&mut state, aad);
            let (blocks, remainder) = data.as_chunks_mut::<16>();
            for block in blocks {
                aegis256_decrypt_block(&mut state, block);
            }
            if !remainder.is_empty() {
                aegis256_decrypt_partial(&mut state, remainder);
            }
            aegis256_finalize::<TAG_SIZE>(&mut state, aad.len(), data.len())
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_init(key: &[u8; 16], nonce: &[u8; 16]) -> [Block; 8] {
            let key = load(*key);
            let nonce = load(*nonce);
            let c0 = load(C0);
            let c1 = load(C1);
            let mut state = [
                xor(key, nonce),
                c1,
                c0,
                c1,
                xor(key, nonce),
                xor(key, c0),
                xor(key, c1),
                xor(key, c0),
            ];
            for _ in 0..10 {
                aegis128l_update(&mut state, nonce, key);
            }
            state
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_update(state: &mut [Block; 8], m0: Block, m1: Block) {
            *state = [
                round(state[7], xor(state[0], m0)),
                round(state[0], state[1]),
                round(state[1], state[2]),
                round(state[2], state[3]),
                round(state[3], xor(state[4], m1)),
                round(state[4], state[5]),
                round(state[5], state[6]),
                round(state[6], state[7]),
            ];
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_absorb(state: &mut [Block; 8], aad: &[u8]) {
            for chunk in aad.chunks(32) {
                let mut block = [0u8; 32];
                block[..chunk.len()].copy_from_slice(chunk);
                let (t0, t1) = load_pair(&block);
                aegis128l_update(state, t0, t1);
            }
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_keystream(state: &[Block; 8]) -> (Block, Block) {
            let z0 = xor(xor(state[1], state[6]), and(state[2], state[3]));
            let z1 = xor(xor(state[2], state[5]), and(state[6], state[7]));
            (z0, z1)
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_encrypt_block(state: &mut [Block; 8], block: &mut [u8; 32]) {
            let (z0, z1) = aegis128l_keystream(state);
            let (t0, t1) = load_pair(block);
            aegis128l_update(state, t0, t1);
            store_pair(block, xor(t0, z0), xor(t1, z1));
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_decrypt_block(state: &mut [Block; 8], block: &mut [u8; 32]) {
            let (z0, z1) = aegis128l_keystream(state);
            let (t0, t1) = load_pair(block);
            let out0 = xor(t0, z0);
            let out1 = xor(t1, z1);
            aegis128l_update(state, out0, out1);
            store_pair(block, out0, out1);
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_decrypt_partial(state: &mut [Block; 8], tail: &mut [u8]) {
            let (z0, z1) = aegis128l_keystream(state);
            let mut block = [0u8; 32];
            block[..tail.len()].copy_from_slice(tail);
            let (t0, t1) = load_pair(&block);
            store_pair(&mut block, xor(t0, z0), xor(t1, z1));
            tail.copy_from_slice(&block[..tail.len()]);
            block[tail.len()..].fill(0);
            let (v0, v1) = load_pair(&block);
            aegis128l_update(state, v0, v1);
        }

        #[target_feature(enable = "aes")]
        fn aegis128l_finalize<const TAG_SIZE: usize>(
            state: &mut [Block; 8],
            aad_len: usize,
            data_len: usize,
        ) -> [u8; TAG_SIZE] {
            const {
                assert!(
                    TAG_SIZE == 16 || TAG_SIZE == 32,
                    "AEGIS tags are 128 or 256 bits"
                );
            }
            let t = xor(state[2], load(lengths(aad_len, data_len)));
            for _ in 0..7 {
                aegis128l_update(state, t, t);
            }
            let low = xor(xor(state[0], state[1]), xor(state[2], state[3]));
            let high = xor(xor(state[4], state[5]), state[6]);
            let mut tag = [0u8; TAG_SIZE];
            if TAG_SIZE == 16 {
                tag.copy_from_slice(&store(xor(low, high)));
            } else {
                tag[..16].copy_from_slice(&store(low));
                tag[16..].copy_from_slice(&store(xor(high, state[7])));
            }
            tag
        }

        #[target_feature(enable = "aes")]
        fn aegis256_init(key: &[u8; 32], nonce: &[u8; 32]) -> [Block; 6] {
            let (k0, k1) = load_pair(key);
            let (n0, n1) = load_pair(nonce);
            let c0 = load(C0);
            let c1 = load(C1);
            let mut state = [xor(k0, n0), xor(k1, n1), c1, c0, xor(k0, c0), xor(k1, c1)];
            for _ in 0..4 {
                aegis256_update(&mut state, k0);
                aegis256_update(&mut state, k1);
                aegis256_update(&mut state, xor(k0, n0));
                aegis256_update(&mut state, xor(k1, n1));
            }
            state
        }

        #[target_feature(enable = "aes")]
        fn aegis256_update(state: &mut [Block; 6], m: Block) {
            *state = [
                round(state[5], xor(state[0], m)),
                round(state[0], state[1]),
                round(state[1], state[2]),
                round(state[2], state[3]),
                round(state[3], state[4]),
                round(state[4], state[5]),
            ];
        }

        #[target_feature(enable = "aes")]
        fn aegis256_absorb(state: &mut [Block; 6], aad: &[u8]) {
            for chunk in aad.chunks(16) {
                let mut block = [0u8; 16];
                block[..chunk.len()].copy_from_slice(chunk);
                aegis256_update(state, load(block));
            }
        }

        #[target_feature(enable = "aes")]
        fn aegis256_keystream(state: &[Block; 6]) -> Block {
            xor(
                xor(xor(state[1], state[4]), state[5]),
                and(state[2], state[3]),
            )
        }

        #[target_feature(enable = "aes")]
        fn aegis256_encrypt_block(state: &mut [Block; 6], block: &mut [u8; 16]) {
            let z = aegis256_keystream(state);
            let t = load(*block);
            aegis256_update(state, t);
            *block = store(xor(t, z));
        }

        #[target_feature(enable = "aes")]
        fn aegis256_decrypt_block(state: &mut [Block; 6], block: &mut [u8; 16]) {
            let z = aegis256_keystream(state);
            let out = xor(load(*block), z);
            aegis256_update(state, out);
            *block = store(out);
        }

        #[target_feature(enable = "aes")]
        fn aegis256_decrypt_partial(state: &mut [Block; 6], tail: &mut [u8]) {
            let z = aegis256_keystream(state);
            let mut block = [0u8; 16];
            block[..tail.len()].copy_from_slice(tail);
            block = store(xor(load(block), z));
            tail.copy_from_slice(&block[..tail.len()]);
            block[tail.len()..].fill(0);
            aegis256_update(state, load(block));
        }

        #[target_feature(enable = "aes")]
        fn aegis256_finalize<const TAG_SIZE: usize>(
            state: &mut [Block; 6],
            aad_len: usize,
            data_len: usize,
        ) -> [u8; TAG_SIZE] {
            const {
                assert!(
                    TAG_SIZE == 16 || TAG_SIZE == 32,
                    "AEGIS tags are 128 or 256 bits"
                );
            }
            let t = xor(state[3], load(lengths(aad_len, data_len)));
            for _ in 0..7 {
                aegis256_update(state, t);
            }
            let low = xor(xor(state[0], state[1]), state[2]);
            let high = xor(xor(state[3], state[4]), state[5]);
            let mut tag = [0u8; TAG_SIZE];
            if TAG_SIZE == 16 {
                tag.copy_from_slice(&store(xor(low, high)));
            } else {
                tag[..16].copy_from_slice(&store(low));
                tag[16..].copy_from_slice(&store(high));
            }
            tag
        }

        #[target_feature(enable = "aes")]
        fn load_pair(block: &[u8; 32]) -> (Block, Block) {
            let (lo, hi) = block.split_at(16);
            (
                load(
                    lo.try_into()
                        .expect("Half block size matches AES block size"),
                ),
                load(
                    hi.try_into()
                        .expect("Half block size matches AES block size"),
                ),
            )
        }

        #[target_feature(enable = "aes")]
        fn store_pair(block: &mut [u8; 32], lo: Block, hi: Block) {
            block[..16].copy_from_slice(&store(lo));
            block[16..].copy_from_slice(&store(hi));
        }

        fn lengths(aad_len: usize, data_len: usize) -> [u8; 16] {
            let mut lengths = [0u8; 16];
            lengths[..8].copy_from_slice(&((aad_len as u64) << 3).to_le_bytes());
            lengths[8..].copy_from_slice(&((data_len as u64) << 3).to_le_bytes());
            lengths
        }
    };
}
