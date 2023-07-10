const std = @import("std");
const crypto = std.crypto;
const debug = std.debug;
const math = std.math;
const mem = std.mem;
const Polyval = crypto.onetimeauth.Polyval;

/// AEAD_AES_128_GCM_SIV: nonce misuse-resistant AEAD.
///
/// References:
/// - https://www.rfc-editor.org/rfc/rfc8452.html
/// - https://cyber.biu.ac.il/aes-gcm-siv/
/// - https://eprint.iacr.org/2017/168
pub const Aes128GcmSiv = AesGcmSiv(crypto.core.aes.Aes128);

/// AEAD_AES_256_GCM_SIV: nonce misuse-resistant AEAD.
///
/// References:
/// - https://www.rfc-editor.org/rfc/rfc8452.html
/// - https://cyber.biu.ac.il/aes-gcm-siv/
/// - https://eprint.iacr.org/2017/168
pub const Aes256GcmSiv = AesGcmSiv(crypto.core.aes.Aes256);

fn AesGcmSiv(comptime Aes: anytype) type {
    comptime debug.assert(Aes.block.block_length == 16);

    return struct {
        pub const tag_length = 16;
        pub const nonce_length = 12;
        pub const key_length = Aes.key_bits / 8;

        pub fn encrypt(
            c: []u8,
            tag: *[tag_length]u8,
            m: []const u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) void {
            debug.assert(c.len == m.len);
            debug.assert(m.len <= 16 * (1 << 32));
            debug.assert(ad.len <= 16 * (1 << 32));

            var mac_key: [Polyval.key_length]u8 = undefined;
            var enc_key: [key_length]u8 = undefined;
            deriveKeys(&mac_key, &enc_key, npub, key);

            const block_count = 1 +
                (math.divCeil(usize, ad.len, Polyval.block_length) catch unreachable) +
                (math.divCeil(usize, m.len, Polyval.block_length) catch unreachable);
            var mac = Polyval.initForBlockCount(&mac_key, block_count);
            mac.update(ad);
            mac.pad();
            mac.update(m);
            mac.pad();
            mac.update(&length_block: {
                var b: [16]u8 = undefined;
                mem.writeIntLittle(u64, b[0..8], ad.len * 8);
                mem.writeIntLittle(u64, b[8..16], m.len * 8);
                break :length_block b;
            });
            var auth: [Polyval.mac_length]u8 = undefined;
            mac.final(&auth);
            for (auth[0..nonce_length], npub) |*a, n| {
                a.* ^= n;
            }
            auth[auth.len - 1] &= 0x7F;

            var aes = Aes.initEnc(enc_key);
            aes.encrypt(tag, &auth);
            var counter_block = tag.*;
            counter_block[counter_block.len - 1] |= 0x80;
            ctr(
                u32,
                @TypeOf(aes),
                aes,
                c,
                m,
                counter_block,
                std.builtin.Endian.Little,
            );
        }

        pub fn decrypt(
            m: []u8,
            c: []const u8,
            tag: [tag_length]u8,
            ad: []const u8,
            npub: [nonce_length]u8,
            key: [key_length]u8,
        ) crypto.errors.AuthenticationError!void {
            debug.assert(c.len == m.len);

            var mac_key: [Polyval.key_length]u8 = undefined;
            var enc_key: [key_length]u8 = undefined;
            deriveKeys(&mac_key, &enc_key, npub, key);

            var aes = Aes.initEnc(enc_key);
            var counter_block = tag;
            counter_block[counter_block.len - 1] |= 0x80;
            ctr(
                u32,
                @TypeOf(aes),
                aes,
                m,
                c,
                counter_block,
                std.builtin.Endian.Little,
            );

            const block_count = 1 +
                (math.divCeil(usize, ad.len, Polyval.block_length) catch unreachable) +
                (math.divCeil(usize, m.len, Polyval.block_length) catch unreachable);
            var mac = Polyval.initForBlockCount(&mac_key, block_count);
            mac.update(ad);
            mac.pad();
            mac.update(m);
            mac.pad();
            mac.update(&length_block: {
                var b: [16]u8 = undefined;
                mem.writeIntLittle(u64, b[0..8], ad.len * 8);
                mem.writeIntLittle(u64, b[8..16], m.len * 8);
                break :length_block b;
            });
            var auth: [Polyval.mac_length]u8 = undefined;
            mac.final(&auth);
            for (auth[0..nonce_length], npub) |*a, n| {
                a.* ^= n;
            }
            auth[auth.len - 1] &= 0x7F;

            var expected_tag: [tag_length]u8 = undefined;
            aes.encrypt(&expected_tag, &auth);

            if (!crypto.utils.timingSafeEql([tag_length]u8, expected_tag, tag)) {
                crypto.utils.secureZero(u8, m);
                return error.AuthenticationFailed;
            }
        }

        inline fn deriveKeys(mac_key: *[Polyval.key_length]u8, enc_key: *[key_length]u8, npub: [nonce_length]u8, key: [key_length]u8) void {
            const aes = Aes.initEnc(key);
            var nonce_counter_block: [16]u8 = undefined;
            nonce_counter_block[4..].* = npub;

            {
                mem.writeIntLittle(u32, nonce_counter_block[0..4], 0);
                var b0: [16]u8 = undefined;
                aes.encrypt(&b0, &nonce_counter_block);

                mem.writeIntLittle(u32, nonce_counter_block[0..4], 1);
                var b1: [16]u8 = undefined;
                aes.encrypt(&b1, &nonce_counter_block);

                mac_key.* = (b0[0..8] ++ b1[0..8]).*;
            }

            {
                mem.writeIntLittle(u32, nonce_counter_block[0..4], 2);
                var b2: [16]u8 = undefined;
                aes.encrypt(&b2, &nonce_counter_block);

                mem.writeIntLittle(u32, nonce_counter_block[0..4], 3);
                var b3: [16]u8 = undefined;
                aes.encrypt(&b3, &nonce_counter_block);

                enc_key[0..16].* = (b2[0..8] ++ b3[0..8]).*;

                if (key_length == 32) {
                    mem.writeIntLittle(u32, nonce_counter_block[0..4], 4);
                    var b4: [16]u8 = undefined;
                    aes.encrypt(&b4, &nonce_counter_block);

                    mem.writeIntLittle(u32, nonce_counter_block[0..4], 5);
                    var b5: [16]u8 = undefined;
                    aes.encrypt(&b5, &nonce_counter_block);

                    enc_key[16..32].* = (b4[0..8] ++ b5[0..8]).*;
                }
            }
        }
    };
}

/// `std.crypto.modes.ctr` but allowing a custom nonce/counter split for the initial counter.
/// For example, with a 128-bit counter block (the default), `0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF_FFFF` wraps around to `0`.
/// With a 32-bit counter (used for AES-GCM and AES-GCM-SIV), it wraps around to `0xFFFF_FFFF_FFFF_FFFF_FFFF_FFFF_0000_0000`.
fn ctr(comptime Counter: type, comptime BlockCipher: anytype, block_cipher: BlockCipher, dst: []u8, src: []const u8, iv: [BlockCipher.block_length]u8, endian: std.builtin.Endian) void {
    debug.assert(dst.len >= src.len);
    const block_length = BlockCipher.block_length;
    var counter = iv;
    var counterInt: Counter = @truncate(mem.readInt(u128, &counter, endian));
    var i: usize = 0;

    const parallel_count = BlockCipher.block.parallel.optimal_parallel_blocks;
    const wide_block_length = parallel_count * block_length;
    if (src.len >= wide_block_length) {
        var counters = iv ** parallel_count;
        while (i + wide_block_length <= src.len) : (i += wide_block_length) {
            inline for (0..parallel_count) |j| {
                mem.writeInt(Counter, counters[j * block_length ..][0..@sizeOf(Counter)], counterInt, endian);
                counterInt +%= 1;
            }
            block_cipher.xorWide(parallel_count, dst[i..][0..wide_block_length], src[i..][0..wide_block_length], counters);
        }
    }
    while (i + block_length <= src.len) : (i += block_length) {
        mem.writeInt(Counter, counter[0..@sizeOf(Counter)], counterInt, endian);
        counterInt +%= 1;
        block_cipher.xor(dst[i..][0..block_length], src[i..][0..block_length], counter);
    }
    if (i < src.len) {
        mem.writeInt(Counter, counter[0..@sizeOf(Counter)], counterInt, endian);
        var pad = [_]u8{0} ** block_length;
        const src_slice = src[i..];
        @memcpy(pad[0..src_slice.len], src_slice);
        block_cipher.xor(&pad, &pad, counter);
        const pad_slice = pad[0 .. src.len - i];
        @memcpy(dst[i..][0..pad_slice.len], pad_slice);
    }
}

test {
    _ = @import("test.zig");
}
