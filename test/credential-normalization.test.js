import test from 'node:test';
import assert from 'node:assert/strict';

import {
    buildShadowsocksUri,
    normalizeUuidCredential,
    parseUuidCredential,
    uuidRegex,
} from '../src/utils/helpers.js';
import { looksLikeGrpcPayload } from '../src/protocols/grpc.js';

const UUID = '00000000-0000-4000-8000-000000000000';

test('UUID normalization removes a leading BOM and surrounding whitespace', () => {
    const normalized = normalizeUuidCredential(` \uFEFF${UUID.toUpperCase()}\r\n`);
    assert.equal(normalized, UUID);
    assert.match(normalized, uuidRegex);
});

test('UUID parser accepts a canonical UUID even when the secret contains a BOM', () => {
    assert.equal(parseUuidCredential(`\uFEFF${UUID}`), UUID);
});

test('UUID parser rejects malformed explicit credentials instead of silently deriving another UUID', () => {
    assert.throws(() => parseUuidCredential('not-a-uuid'), /canonical version-4 UUID/);
});

test('gRPC sniffing distinguishes framed hunk data from XHTTP payloads', async () => {
    const grpcFrame = new Uint8Array([0, 0, 0, 0, 2, 0x0a, 0]);
    const xhttpPayload = new Uint8Array([0, 0, 0, 0, 0, 1, 2]);
    assert.equal(await looksLikeGrpcPayload(new Request('https://worker.example/tunnel', {
        method: 'POST',
        body: grpcFrame,
    })), true);
    assert.equal(await looksLikeGrpcPayload(new Request('https://worker.example/tunnel', {
        method: 'POST',
        body: xhttpPayload,
    })), false);
});

test('generated Shadowsocks v2ray-plugin links disable mux', () => {
    const link = buildShadowsocksUri({
        password: UUID,
        address: 'worker.example',
        host: 'worker.example',
        path: '/tunnel',
    });
    const plugin = new URL(link).searchParams.get('plugin');
    assert.match(plugin, /(?:^|;)mux=0(?:;|$)/);
});
