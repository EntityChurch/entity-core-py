# EXTENSION-CONTENT v3.5 — cross-impl conformance vectors

**Spec reference:** `EXTENSION-CONTENT.md` v3.5 §3.6.5
**Generator:** `entity-core-py` (regenerate via `docs/conformance/content-v3.5/generate_vectors.py`)

These are the four conformance-vector surfaces named in §3.6.5. Sibling-impl regeneration MUST produce byte-identical values in every field. Mismatches indicate cross-impl divergence at the boundary the field grades (gear table → §3.6.1 derivation; boundary vectors → §3.6.3 algorithm; ECF byte equality → `ENTITY-CBOR-ENCODING.md` §4.2 + the §2.8 wire-shape pin).

---

## Surface 1 — Gear table (first 16 entries, §3.6.1)

| i | preimage (hex) | value_uint64 | first 8 bytes LE (hex) |
|---|---|---|---|
| 0 | `4661737443444300` | `1060420904190572648` | `6878adaa315fb70e` |
| 1 | `4661737443444301` | `8160819590344035158` | `564b81f62d0e4171` |
| 2 | `4661737443444302` | `3753481100135370058` | `4a0db67c2c0b1734` |
| 3 | `4661737443444303` | `11167746503106172732` | `3c17417b46cefb9a` |
| 4 | `4661737443444304` | `14808702327341895650` | `e2cfb68d4e1483cd` |
| 5 | `4661737443444305` | `2940648694560438010` | `fab67d506848cf28` |
| 6 | `4661737443444306` | `9814474743742705020` | `7cadd3b5c7043488` |
| 7 | `4661737443444307` | `627016397810509787` | `db27d77b179cb308` |
| 8 | `4661737443444308` | `12037391942287534337` | `01a932d631680da7` |
| 9 | `4661737443444309` | `13457774580841221829` | `c58e52cead9ec3ba` |
| 10 | `466173744344430a` | `18412821768808939403` | `8bbf6fead77b87ff` |
| 11 | `466173744344430b` | `4697805245464702813` | `5defe30ffbf43141` |
| 12 | `466173744344430c` | `14102030389498117551` | `af7dcc69ec79b4c3` |
| 13 | `466173744344430d` | `922128436773927351` | `b7393277ed0ecc0c` |
| 14 | `466173744344430e` | `15072379312106321969` | `31380ba220d92bd1` |
| 15 | `466173744344430f` | `3086188392143727530` | `aa2ba9c7fd57d42a` |

## Surface 2 — Fixed-size chunking boundaries (§3.2)

- **zeros_4mib** (4194304 bytes) at `chunk_size=65536` → `64` chunks, blob hash `00eb2cdb3469489ccfa59f1dd15360f5926a1b1d48bf240b9ab466f9fc21d3a079`.
- **zeros_4mib** (4194304 bytes) at `chunk_size=4194304` → `1` chunks, blob hash `004f39f719cd8e8398ed6bbe00118901ec2eda28c2feebea514f3b84c2b881efd0`.
- **zeros_512kib** (524288 bytes) at `chunk_size=65536` → `8` chunks, blob hash `0024d69085d85ccbe3ee187e2ab5bece84c4dba6529ad6d2587210d8e13eacaaa1`.
- **ramp_4mib** (4194304 bytes) at `chunk_size=65536` → `64` chunks, blob hash `004892c39bb4312d16235aa6d6b85bd6fd09a4ca49dde5591b74c828917381b9cd`.
- **ramp_4mib** (4194304 bytes) at `chunk_size=4194304` → `1` chunks, blob hash `00ba442a03da969449bf6a2d5559c76c8bebbf0703ac65f84af4b22246a8ea0ddf`.
- **sha256_stream_2mib** (2097152 bytes) at `chunk_size=65536` → `32` chunks, blob hash `005c3adcbcd3c86d165389a2288c4ad2b585aab8dae8fe884a8a7ccb035a2eedf6`.
- **sha256_stream_2mib** (2097152 bytes) at `chunk_size=4194304` → `1` chunks, blob hash `00d5ef89eae4aef299a70277fe56ffb3eff422773363113dd416ec968e64825752`.

## Surface 3a — FastCDC chunking boundaries (§3.6)

- **zeros_4mib** (4194304 bytes) at `target_size=65536` → `32` chunks, blob hash `0039faeadcdca95a3ce89e6ab4d3a2d2b614190a637c07351fcab588b743601c9d`.
- **zeros_4mib** (4194304 bytes) at `target_size=4194304` → `1` chunks, blob hash `000b919bdc13415857f7bcd5f1df0a2132b877b19e60b60f5e26baf6471031c09b`.
- **zeros_512kib** (524288 bytes) at `target_size=65536` → `4` chunks, blob hash `007822e65a34d983287081c39f95fc8c1faccbbb851b87d6186199e274405d8360`.
- **ramp_4mib** (4194304 bytes) at `target_size=65536` → `32` chunks, blob hash `0083f26262fc78981f88ee4038230738c3939c556cb102a128ceaa9cd7dbc3c284`.
- **ramp_4mib** (4194304 bytes) at `target_size=4194304` → `1` chunks, blob hash `005dcdb23e28dab228eb674f340ae570698b1273dfcefe2a5310bdf3bdecb5cfe2`.
- **sha256_stream_2mib** (2097152 bytes) at `target_size=65536` → `29` chunks, blob hash `00845832a1f83395e70fa95e8d33a84ed64064acb80418c745021e36b5618a44b4`.
- **sha256_stream_2mib** (2097152 bytes) at `target_size=4194304` → `1` chunks, blob hash `00f25bbc5c3fbd42c79423527dd443306646d87fb5d0898800409afce7afe223c2`.

## Surface 3b — FastCDC edit-stability (§3.6.5, load-bearing)

1-byte insertion at a known offset; sibling impls MUST produce the same edited-blob hash, the same chunk counts, and the same stable-prefix / resynced-tail measurements.

- **sha256_stream_2mib** (2097152 bytes) @ target=65536, insertion at offset=102400 byte=`0x5A`:
  - original blob hash `00845832a1f83395e70fa95e8d33a84ed64064acb80418c745021e36b5618a44b4` (29 chunks)
  - edited blob hash `002557c9653e77f6b957a93ae365d57ecf43e936e58015f177dfeebb3445777f4c` (29 chunks)
  - stable prefix chunks (identical leading run): `1`
  - resynced tail chunks (identical trailing run): `27`

## Surface 4 — ECF byte-equality for content entities (§2.1 / §2.2 / §2.4)

Same `{type, data}` → same canonical bytes → same entity hash. Cross-impl drift here would break content dedup silently — same class of risk that drove `ENTITY-CBOR-ENCODING.md` Appendix E.

| case | type | entity hash (hex) | ECF bytes (hex, prefix) |
|---|---|---|---|
| `chunk_128B` | `system/content/chunk` | `004c1289b044a87b3276a97e7d3517ad9b795601436a994892b8a3834ac3ddc868` | `a26464617461a1677061796c6f616458800102030401020304010203040102030401020304010203…` |
| `blob_2chunks_4mib_fastcdc` | `system/content/blob` | `0026a5f7a3060e574d6d5cc9554da942ad96508b12d90f915859834bb3bfd613b1` | `a26464617461a4666368756e6b7382582100a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0a0…` |
| `descriptor_media_type_only` | `system/content/descriptor` | `00d1135b70d90ca8c1f7ac62c847a49f32a18a8b77c39957b8aedb602bb4342473` | `a26464617461a267636f6e74656e7458210042424242424242424242424242424242424242424242…` |

Full ECF bytes per case live in `content-vectors.json` (field `vectors.ecf_byte_equality[].ecf_bytes_hex`).
