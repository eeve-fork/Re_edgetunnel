import test from 'node:test';
import assert from 'node:assert/strict';

import {
    CLOUDFLARE_HOST,
    CLOUDFLARE_PATH,
    generateClashConfig,
    loadConfig,
} from '../workers/clash-sub/index.js';

const UUID = '00000000-0000-4000-8000-000000000000';

function environment(uuid = `\uFEFF${UUID}`) {
    return {
        SECRET_TOKEN: 'subscription-token',
        PAGE_PASSWORD: 'page-password',
        CLOUDFLARE_UUID: uuid,
        NODES_JSON: JSON.stringify([
            { name: 'existing', type: 'hysteria2', server: 'node.example', port: 443, password: 'test' },
            { name: 'old-upcloud', type: 'mieru', server: 'upcloud.example', port: 443, username: 'u', password: 'p' },
        ]),
    };
}

test('subscription configuration strips UUID BOM and retains non-managed nodes', () => {
    const config = loadConfig(environment());
    assert.equal(config.nodes[0].name, 'existing');
    assert.equal(config.nodes.some((node) => node.name === 'old-upcloud'), false);
    const cloudflare = config.nodes.filter((node) => node.name.startsWith('cloudflare-'));
    assert.equal(cloudflare.length, 7);
    for (const node of cloudflare) {
        assert.equal(node.server, CLOUDFLARE_HOST);
        assert.equal((node.uuid || node.password).includes('\uFEFF'), false);
        assert.equal(node.udp, false);
    }
});

test('generated Clash YAML uses dedicated tunnel routing and clean credentials', () => {
    const yaml = generateClashConfig(loadConfig(environment()).nodes);
    assert.doesNotMatch(yaml, /\uFEFF/);
    assert.match(yaml, new RegExp(`server: "${CLOUDFLARE_HOST.replaceAll('.', '\\.')}"`));
    assert.match(yaml, new RegExp(`path: "${CLOUDFLARE_PATH}"`));
    assert.match(yaml, /grpc-service-name: "tunnel"/);
    assert.match(yaml, /cloudflare-vless-ws[\s\S]*?udp: false/);
    assert.doesNotMatch(yaml, /cloudflare-trojan-xhttp/);
});

test('subscription configuration rejects malformed UUID secrets', () => {
    assert.throws(() => loadConfig(environment('not-a-uuid')), /canonical version-4 UUID/);
});
