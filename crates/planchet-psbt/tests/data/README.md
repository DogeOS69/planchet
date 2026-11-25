# Fixture provenance

`bip174.json`: the 20 invalid and 14 valid codec examples from
<https://github.com/bitcoin/bips/blob/master/bip-0174.mediawiki>, retrieved
2026-11-24 (BIP174 version 1.4.4). Hex and expected classification are copied
without regenerating them. BIP174's BSD-2-Clause license is retained below.

`core-sighash.json`: eight representative rows with nontrivial scriptCode from
<https://github.com/dogecoin/dogecoin/blob/v1.14.9/src/test/data/sighash.json>.
Raw transaction, script, input index, signed 32-bit hash type and expected hash
are copied unchanged. Core displays uint256 hashes in reverse digest order.
The source is MIT licensed, Copyright (c) the Bitcoin Core developers and the
Dogecoin Core developers; see <https://github.com/dogecoin/dogecoin/blob/v1.14.9/COPYING>.

## BIP174 BSD-2-Clause

Author: Ava Chow. The source declares the 2-clause BSD license without
specifying a separate copyright year.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
