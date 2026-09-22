#!/usr/bin/env python3
# Tests for the delv write paths: creating, modifying and re-serializing
# archives, patches, maps and images.
#
# Why these exist: the Python 3 compatibility work was validated against
# real "Cythera Data" -- but only by *reading* it. Every check in the
# cythera repository's harnesses is read-only too, so the write half of
# the library (which is what an editor lives on) had no coverage at all,
# and it turned out to hold several bugs that no reader ever hits:
# text into set_data, raw bytes through Archive.__setitem__, de-novo
# resources in encrypted subindexes, Patch.patch_info, Map serialization,
# DelvImage(None). Each test here pins one of those.
#
# Everything runs on synthetic archives; no game data is required. If a
# real archive is present (reference/Cythera Data extracted somewhere and
# named by $DELV_TEST_ARCHIVE), one extra test round-trips it byte for
# byte; otherwise that test skips.

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import delv
import delv.archive
import delv.graphics
import delv.level
import delv.store
import delv.util
from delv.archive import (Scenario, Patch, Resource, resid,
                          constant_keystream, decrypt, entropy)


def build_scenario():
    """A small scenario exercising an encrypted subindex (1), a clear one
       (3), and one the tables say nothing about (60)."""
    a = Scenario()
    a[0x0200] = b'\x01\x02\x03encrypted subindex payload'
    a[0x0210] = b'single_known says this one is clear'
    a[0x0400] = 'text resource in a clear subindex'
    a[0x3D07] = bytes(range(256))
    return a


class TestResourceWrites(unittest.TestCase):
    def test_set_data_accepts_text(self):
        a = Scenario()
        a[0xBC00] = "This file written by delv %s" % delv.version
        self.assertTrue(bytes(a[0xBC00]).startswith(b'This file written'))

    def test_set_data_accepts_bytes(self):
        a = Scenario()
        a[0xBC00] = b'\x00\x01\x02'
        self.assertEqual(bytes(a[0xBC00]), b'\x00\x01\x02')

    def test_resource_setitem_slice_accepts_text(self):
        a = Scenario()
        a[0xBC00] = b'0123456789'
        a.get(0xBC00)[3:6] = 'hax'
        self.assertEqual(bytes(a[0xBC00]), b'012hax6789')

    def test_str_returns_text_not_repr(self):
        a = Scenario()
        a[0xBC00] = b'hello'
        self.assertEqual(str(a.get(0xBC00)), 'hello')


class TestArchiveConsistency(unittest.TestCase):
    def test_raw_setitem_registers_subindex(self):
        # Assigning raw bytes used to populate all_subindices without
        # touching master_index, so the archive claimed to be empty.
        a = Scenario()
        a[0x0400] = b'data'
        self.assertIn(3, a.subindices())
        self.assertEqual(a.resource_ids(), [0x0400])
        self.assertEqual(len(list(a)), 1)

    def test_empty_archive_iterates_empty(self):
        a = Scenario()
        self.assertEqual(a.resource_ids(), [])
        self.assertEqual(a.resources(), [])
        self.assertEqual(list(a), [])


class TestRoundTrip(unittest.TestCase):
    def test_de_novo_round_trip_byte_exact(self):
        a = build_scenario()
        first = a.to_string()
        b = Scenario()
        b.from_string(first)
        second = b.to_string()
        self.assertEqual(first, second)

    def test_encrypted_subindex_round_trips_plaintext(self):
        # The de-novo resource in known-encrypted subindex 1 must come
        # back as the plaintext that went in -- before the canon_encryption
        # seed in Resource.__init__ it came back XOR-scrambled.
        a = build_scenario()
        b = Scenario()
        b.from_string(a.to_string())
        self.assertEqual(bytes(b[0x0200]),
                         b'\x01\x02\x03encrypted subindex payload')
        # And it must actually be stored encrypted on disk, not just
        # readable back: the raw file bytes at its offset differ from
        # the plaintext.
        raw = a.to_string()
        self.assertNotIn(b'encrypted subindex payload', raw)

    def test_single_known_clear_resource_stays_clear(self):
        a = build_scenario()
        raw = a.to_string()
        self.assertIn(b'single_known says this one is clear', raw)

    def test_modify_and_round_trip(self):
        a = build_scenario()
        b = Scenario()
        b.from_string(a.to_string())
        b.get(0x0400).set_data('changed')
        c = Scenario()
        c.from_string(b.to_string())
        self.assertEqual(bytes(c[0x0400]), b'changed')

    def test_real_archive_round_trip(self):
        path = os.environ.get('DELV_TEST_ARCHIVE')
        if not path or not os.path.isfile(path):
            self.skipTest('set DELV_TEST_ARCHIVE to a Cythera Data file')
        a = Scenario(path)
        for r in a.resources():
            if not r.loaded:
                r.load()
        out = a.to_string()
        b = Scenario()
        b.from_string(out)
        for rid in a.resource_ids():
            self.assertEqual(bytes(a[rid]), bytes(b[rid]),
                             'resource %04X changed in round trip' % rid)


class TestEncryptionGuess(unittest.TestCase):
    """decrypt_if_required, the guess made for a subindex the tables do not
       cover -- which in practice is a modified archive."""

    def test_constant_keystream_ids_exist_and_are_few(self):
        # The claim the guess now rests on: the keystream degenerates to one
        # repeated byte for a small, fixed set of resource ids. If this count
        # ever moves, the cipher has been misread somewhere.
        ids = [r for r in range(0x0100, 0x10000)
               if constant_keystream(r) is not None]
        self.assertEqual(len(ids), 120)
        self.assertIn(0x1402, ids)
        self.assertIn(0xF014, ids)
        # and they are confined to these subindexes
        self.assertEqual(sorted({(r >> 8) - 1 for r in ids}),
                         [19, 47, 63, 83, 111, 127, 147, 175, 191, 211, 239])

    def test_entropy_cannot_see_a_constant_keystream(self):
        # Why the special case has to exist at all: a constant XOR permutes
        # byte values, so entropy() returns the SAME number for cleartext and
        # ciphertext -- exactly, not approximately -- and the `>` test in
        # decrypt_if_required is therefore always False.
        resid_const = 0x1402
        self.assertIsNotNone(constant_keystream(resid_const))
        clear = bytearray(b'\x00\x00\x01Od_Shutter1\x00' * 8)
        cipher = decrypt(clear, resid_const)
        self.assertEqual(entropy(clear), entropy(cipher))

    def test_constant_keystream_resource_is_decrypted(self):
        # A resource in a subindex nothing knows about, at an id whose
        # keystream is constant. Before the zero-byte rule this came back
        # still encrypted, every time.
        rid = resid(63, 0)                     # subindex 63: no table covers it
        self.assertIsNotNone(constant_keystream(rid))
        payload = b'\x00\x00\x01itsState\x00\x00\x02itsLights\x00' * 4
        a = Scenario()
        a[rid] = payload
        b = Scenario()
        b.from_string(a.to_string())
        self.assertEqual(bytes(b[rid]), payload)

    def test_reading_and_writing_are_silent_on_stdout(self):
        # Four functions used to trace normal operation to stdout -- the
        # encryption guess, "Writing out to", "creating new resource" and
        # "map loading" -- which any tool reading delv's output on a pipe had
        # to filter. Warnings and diagnostics still go out, to stderr.
        # This covers a whole build-write-read cycle, so it guards all four
        # rather than only the guess.
        import io, contextlib
        rid = resid(63, 1)                     # no table covers subindex 63
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            a = Scenario()
            a[rid] = b'\x00\x00\x01itsState\x00' * 4
            a[0x0200] = b'\x01\x02\x03encrypted subindex payload'
            raw = a.to_string()
            b = Scenario()
            b.from_string(raw)
            bytes(b[rid])
            bytes(b[0x0200])
        self.assertEqual(buf.getvalue(), '')


class TestPatch(unittest.TestCase):
    def test_patch_info_twice(self):
        # The second call used to raise "'bytes' object is not callable"
        # because the method rebound its own name on the instance.
        p = Patch()
        p.patch_info('first')
        p.patch_info('second')
        self.assertEqual(p.get_patch_info(), 'second')
        self.assertEqual(bytes(p[0xFFFF]), b'MAGPYsecond')

    def test_magpie_format_read(self):
        p = Patch()
        data = bytearray(0x200)
        info = b'A Magpie patch'
        data[0x138] = len(info)
        data[0x139:0x139 + len(info)] = info
        p[0xFFFF] = bytes(data)
        self.assertEqual(p.get_patch_info(), 'A Magpie patch')

    def test_diff_and_patch(self):
        base = build_scenario()
        modified = Scenario()
        modified.from_string(base.to_string())
        modified.get(0x0400).set_data('modified text')
        modified[0x0401] = b'brand new resource'

        p = Patch()
        p.patch_info('test patch')
        p.diff(base, modified)
        self.assertEqual(sorted(p.resource_ids()),
                         [0x0400, 0x0401, 0xFFFF])

        # Round-trip the patch through its own file format, then apply.
        p2 = Patch()
        p2.from_string(p.to_string())
        target = Scenario()
        target.from_string(base.to_string())
        p2.patch(target)
        self.assertEqual(bytes(target[0x0400]), b'modified text')
        self.assertEqual(bytes(target[0x0401]), b'brand new resource')
        # Untouched resources stay untouched.
        self.assertEqual(bytes(target[0x0200]), bytes(base[0x0200]))

    def test_compatible(self):
        base = build_scenario()
        m1 = Scenario(); m1.from_string(base.to_string())
        m1.get(0x0400).set_data('one')
        m2 = Scenario(); m2.from_string(base.to_string())
        m2.get(0x0400).set_data('two')
        p1 = Patch(); p1.diff(base, m1)
        p2 = Patch(); p2.diff(base, m2)
        self.assertFalse(p1.compatible(p2))
        m3 = Scenario(); m3.from_string(base.to_string())
        m3.get(0x0210).set_data('three')
        p3 = Patch(); p3.diff(base, m3)
        self.assertTrue(p1.compatible(p3))


class TestMap(unittest.TestCase):
    def build_map_bytes(self, w=4, h=3, roof=2):
        bh = delv.util.BinaryHandler(bytearray())
        bh.write_uint16(w); bh.write_uint16(h)
        bh.write_uint16(0)              # unknown, asserted zero
        bh.write_uint16(roof); bh.write_uint16(roof)
        bh.write_uint8(1); bh.write_uint8(1)   # edge propagation
        for zp in (0x8010, 0x8011, 0x8012, 0x8013):
            bh.write_uint16(zp)
        bh.write(bytes(12))             # padding, asserted zero
        for i in range((0x40 * roof * 2) // 2):
            bh.write_uint16(i & 0xFFFF)
        for i in range(w * h):
            bh.write_uint16(0x100 + i)
        bh.seek(0)
        return bh.read()

    def test_map_round_trip(self):
        # Map gained write_to_bfile; it must invert load_from_bfile
        # exactly, since Store.get_data depends on it.
        raw = self.build_map_bytes()
        m = delv.level.Map(bytearray(raw))
        out = bytes(m.get_data())
        self.assertEqual(out, raw)

    def test_map_edit_round_trip(self):
        raw = self.build_map_bytes()
        m = delv.level.Map(bytearray(raw))
        m.map_data[0] = 0x1FF
        out = bytes(m.get_data())
        m2 = delv.level.Map(bytearray(out))
        self.assertEqual(m2.get_tile(0, 0), 0x1FF)
        self.assertEqual(m2.width, m.width)
        self.assertEqual(list(m2.roof_data), list(m.roof_data))


class TestGraphics(unittest.TestCase):
    def test_delv_image_none_source(self):
        # The documented "create an empty image" constructor; it used to
        # assert inside Store.set_source.
        img = delv.graphics.TileSheet(None)
        self.assertEqual(len(img.get_logical_image()),
                         img.logical_width * img.logical_height)

    def test_compress_decompress_round_trip(self):
        img = delv.graphics.TileSheet(None)
        pixels = bytearray(
            (x ^ y) & 0xFF
            for y in range(img.logical_height)
            for x in range(img.logical_width))
        img.set_image(pixels)
        compressed = img.compress(img.get_logical_image())
        img2 = delv.graphics.TileSheet(bytearray(compressed))
        self.assertEqual(bytes(img2.get_logical_image()), bytes(pixels))


class TestStore(unittest.TestCase):
    def test_store_accepts_empty_source(self):
        # An empty resource is a valid binding; it used to assert.
        s = delv.store.TileNameList(bytearray())
        self.assertEqual(len(s.get_names()) if hasattr(s, 'get_names')
                         else 0, 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
