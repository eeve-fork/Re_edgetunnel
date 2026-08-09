const textEncoder = new TextEncoder();

export const CLOUDFLARE_HOST = 'edgetunnel.w0x7ce.eu';
export const CLOUDFLARE_PATH = '/tunnel';
const UUID_PATTERN = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-4[0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$/;
const CLOUDFLARE_NODE_NAMES = new Set([
    'cloudflare-vless-ws',
    'cloudflare-vless-xhttp',
    'cloudflare-vless-grpc',
    'cloudflare-trojan-ws',
    'cloudflare-trojan-xhttp',
    'cloudflare-trojan-grpc',
    'cloudflare-shadowsocks-ws',
]);
const NO_STORE_HEADERS = {
    'cache-control': 'no-store, private, max-age=0',
    'x-content-type-options': 'nosniff',
    'x-robots-tag': 'noindex, nofollow, noarchive',
};

export function normalizeUuidCredential(value) {
    if (typeof value !== 'string') return '';
    return value.trim().replace(/^\uFEFF+/, '').trim().toLowerCase();
}

function response(body, status = 200, headers = {}) {
    return new Response(body, { status, headers: { ...NO_STORE_HEADERS, ...headers } });
}

function textResponse(body, contentType, filename, isHead) {
    return new Response(isHead ? null : body, {
        status: 200,
        headers: {
            ...NO_STORE_HEADERS,
            'content-type': contentType,
            'content-disposition': `inline; filename="${filename}"`,
        },
    });
}

function yamlQuote(value) {
    return JSON.stringify(String(value));
}

function safeEqual(left, right) {
    if (typeof left !== 'string' || typeof right !== 'string') return false;
    const leftBytes = textEncoder.encode(left);
    const rightBytes = textEncoder.encode(right);
    if (leftBytes.length !== rightBytes.length) return false;
    let difference = 0;
    for (let index = 0; index < leftBytes.length; index += 1) {
        difference |= leftBytes[index] ^ rightBytes[index];
    }
    return difference === 0;
}

function escapeHtml(value) {
    return String(value).replace(/[&<>"']/g, (character) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
    })[character]);
}

function formatAuthority(server, port) {
    const host = String(server).includes(':') && !String(server).startsWith('[')
        ? `[${server}]`
        : server;
    return `${host}:${port}`;
}

function base64(value) {
    const bytes = textEncoder.encode(String(value));
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return btoa(binary);
}

export function cloudflareNodes(uuidInput) {
    const uuid = normalizeUuidCredential(uuidInput);
    if (!UUID_PATTERN.test(uuid)) throw new Error('CLOUDFLARE_UUID must be a canonical version-4 UUID');
    const common = {
        server: CLOUDFLARE_HOST,
        port: 443,
        uuid,
        sni: CLOUDFLARE_HOST,
        fingerprint: 'chrome',
        skipCertVerify: false,
        udp: false,
        wsPath: CLOUDFLARE_PATH,
        wsHost: CLOUDFLARE_HOST,
        xhttpPath: CLOUDFLARE_PATH,
        xhttpHost: CLOUDFLARE_HOST,
        xhttpMode: 'stream-one',
        grpcServiceName: 'tunnel',
    };
    return [
        { ...common, name: 'cloudflare-vless-ws', type: 'vless', network: 'ws' },
        { ...common, name: 'cloudflare-vless-xhttp', type: 'vless', network: 'xhttp' },
        { ...common, name: 'cloudflare-vless-grpc', type: 'vless', network: 'grpc' },
        { ...common, name: 'cloudflare-trojan-ws', type: 'trojan', network: 'ws', password: uuid },
        { ...common, name: 'cloudflare-trojan-xhttp', type: 'trojan', network: 'xhttp', password: uuid },
        { ...common, name: 'cloudflare-trojan-grpc', type: 'trojan', network: 'grpc', password: uuid },
        {
            name: 'cloudflare-shadowsocks-ws',
            type: 'ss',
            server: CLOUDFLARE_HOST,
            port: 443,
            method: 'aes-128-gcm',
            password: uuid,
            udp: false,
            plugin: 'v2ray-plugin',
            pluginMode: 'websocket',
            pluginTls: true,
            pluginHost: CLOUDFLARE_HOST,
            pluginPath: `${CLOUDFLARE_PATH}?enc=aes-128-gcm`,
            pluginMux: false,
        },
    ];
}

function nodeText(node) {
    return [node?.name, node?.server, node?.shareLink].filter(Boolean).join(' ').toLowerCase();
}

function isUpCloudNode(node) {
    return nodeText(node).includes('upcloud');
}

function validateNode(node) {
    if (!node || !node.name || !node.type || !node.server || !node.port) {
        throw new Error('Every node needs name, type, server and port');
    }
}

export function loadConfig(env) {
    const required = ['SECRET_TOKEN', 'PAGE_PASSWORD', 'NODES_JSON', 'CLOUDFLARE_UUID'];
    const missing = required.filter((key) => !env[key]);
    if (missing.length) throw new Error(`Missing Worker secrets: ${missing.join(', ')}`);

    let originalNodes;
    try {
        originalNodes = JSON.parse(env.NODES_JSON);
    } catch {
        throw new Error('NODES_JSON is not valid JSON');
    }
    if (!Array.isArray(originalNodes)) throw new Error('NODES_JSON must be an array');

    const retainedNodes = originalNodes.filter((node) =>
        !isUpCloudNode(node) && !CLOUDFLARE_NODE_NAMES.has(node?.name));
    const nodes = [...retainedNodes, ...cloudflareNodes(env.CLOUDFLARE_UUID)];
    const names = new Set();
    for (const node of nodes) {
        validateNode(node);
        if (names.has(node.name)) throw new Error(`Duplicate node name: ${node.name}`);
        names.add(node.name);
    }

    const token = env.SECRET_TOKEN;
    return {
        token,
        pagePassword: env.PAGE_PASSWORD,
        nodes,
        paths: {
            legacy: `/sub/${token}.yaml`,
            clash: `/sub/${token}/clash.yaml`,
            links: `/sub/${token}/links.txt`,
        },
    };
}

function isClashSupported(node) {
    if (['hysteria2', 'mieru', 'ss', 'shadowsocks'].includes(node.type)) return true;
    if (node.type === 'vless') return ['ws', 'xhttp', 'grpc', 'tcp', undefined].includes(node.network);
    if (node.type === 'trojan') return ['ws', 'grpc', 'tcp', undefined].includes(node.network);
    return false;
}

function clashNode(node) {
    const type = node.type === 'shadowsocks' ? 'ss' : node.type;
    const lines = [
        `  - name: ${yamlQuote(node.name)}`,
        `    type: ${type}`,
        `    server: ${yamlQuote(node.server)}`,
        `    port: ${node.port}`,
    ];

    if (node.type === 'hysteria2') {
        const obfsEnabled = node.obfsEnabled !== false;
        lines.push(`    password: ${yamlQuote(node.password)}`);
        if (node.sni) lines.push(`    sni: ${yamlQuote(node.sni)}`);
        if (node.skipCertVerify !== undefined) lines.push(`    skip-cert-verify: ${node.skipCertVerify ? 'true' : 'false'}`);
        if (node.fingerprint) lines.push(`    fingerprint: ${yamlQuote(node.fingerprint)}`);
        if (obfsEnabled && node.obfs) lines.push(`    obfs: ${yamlQuote(node.obfs)}`);
        if (obfsEnabled && node.obfsPassword) lines.push(`    obfs-password: ${yamlQuote(node.obfsPassword)}`);
        if (node.up) lines.push(`    up: ${yamlQuote(node.up)}`);
        if (node.down) lines.push(`    down: ${yamlQuote(node.down)}`);
        return lines;
    }

    if (node.type === 'mieru') {
        lines.push(
            `    username: ${yamlQuote(node.username)}`,
            `    password: ${yamlQuote(node.password)}`,
            `    transport: ${yamlQuote(node.transport || 'TCP')}`,
        );
        if (node.multiplexing) lines.push(`    multiplexing: ${yamlQuote(node.multiplexing)}`);
        if (node.udp !== undefined) lines.push(`    udp: ${node.udp ? 'true' : 'false'}`);
        return lines;
    }

    if (node.type === 'vless') {
        const network = node.network || 'tcp';
        lines.push(
            `    uuid: ${yamlQuote(node.uuid)}`,
            `    udp: ${node.udp === true ? 'true' : 'false'}`,
            '    tls: true',
            `    servername: ${yamlQuote(node.sni || node.servername || node.server)}`,
            `    client-fingerprint: ${yamlQuote(node.fingerprint || node.clientFingerprint || 'chrome')}`,
            `    skip-cert-verify: ${node.skipCertVerify ? 'true' : 'false'}`,
            '    encryption: ""',
            `    network: ${network}`,
        );
        if (network === 'ws') {
            lines.push(
                '    ws-opts:',
                `      path: ${yamlQuote(node.wsPath || CLOUDFLARE_PATH)}`,
                '      headers:',
                `        Host: ${yamlQuote(node.wsHost || node.sni || node.server)}`,
            );
        } else if (network === 'xhttp') {
            lines.push(
                '    xhttp-opts:',
                `      path: ${yamlQuote(node.xhttpPath || CLOUDFLARE_PATH)}`,
                `      host: ${yamlQuote(node.xhttpHost || node.sni || node.server)}`,
                `      mode: ${yamlQuote(node.xhttpMode || 'stream-one')}`,
            );
        } else if (network === 'grpc') {
            lines.push('    grpc-opts:', `      grpc-service-name: ${yamlQuote(node.grpcServiceName || 'tunnel')}`);
        }
        return lines;
    }

    if (node.type === 'trojan') {
        const network = node.network || 'tcp';
        lines.push(
            `    password: ${yamlQuote(node.password)}`,
            `    udp: ${node.udp === true ? 'true' : 'false'}`,
            `    sni: ${yamlQuote(node.sni || node.server)}`,
            `    client-fingerprint: ${yamlQuote(node.fingerprint || node.clientFingerprint || 'chrome')}`,
            `    skip-cert-verify: ${node.skipCertVerify ? 'true' : 'false'}`,
            `    network: ${network}`,
        );
        if (network === 'ws') {
            lines.push(
                '    ws-opts:',
                `      path: ${yamlQuote(node.wsPath || CLOUDFLARE_PATH)}`,
                '      headers:',
                `        Host: ${yamlQuote(node.wsHost || node.sni || node.server)}`,
            );
        } else if (network === 'grpc') {
            lines.push('    grpc-opts:', `      grpc-service-name: ${yamlQuote(node.grpcServiceName || 'tunnel')}`);
        }
        return lines;
    }

    if (node.type === 'ss' || node.type === 'shadowsocks') {
        lines.push(
            `    cipher: ${yamlQuote(node.method || node.cipher || 'aes-128-gcm')}`,
            `    password: ${yamlQuote(node.password)}`,
            `    udp: ${node.udp === true ? 'true' : 'false'}`,
        );
        if (node.plugin) {
            lines.push(
                `    plugin: ${node.plugin}`,
                '    plugin-opts:',
                `      mode: ${yamlQuote(node.pluginMode || 'websocket')}`,
                `      tls: ${node.pluginTls ? 'true' : 'false'}`,
                ...(node.pluginMux === false ? ['      mux: false'] : []),
                `      host: ${yamlQuote(node.pluginHost || node.server)}`,
                `      path: ${yamlQuote(node.pluginPath || '/')}`,
            );
        }
        return lines;
    }

    throw new Error(`Unsupported node type: ${node.type}`);
}

export function generateClashConfig(nodes) {
    const clashNodes = nodes.filter(isClashSupported);
    if (!clashNodes.length) throw new Error('No Clash-compatible nodes available');
    const lines = [
        '# For scanned Cloudflare IPs, change only server on cloudflare-* nodes.',
        '# Keep servername/sni, Host and tunnel path unchanged.',
        'mode: rule',
        '',
        'proxies:',
    ];
    for (const node of clashNodes) lines.push(...clashNode(node));
    lines.push('', 'proxy-groups:', '  - name: "PROXY"', '    type: select', '    proxies:');
    for (const node of clashNodes) lines.push(`      - ${yamlQuote(node.name)}`);
    lines.push('      - DIRECT', '', 'rules:', '  - GEOIP,LAN,DIRECT', '  - GEOIP,CN,DIRECT', '  - MATCH,PROXY');
    return `${lines.join('\n')}\n`;
}

function linkQuery(node, includeEncryption = false) {
    const query = new URLSearchParams({
        security: 'tls',
        type: node.network || 'tcp',
        host: node.host || node.server,
        fp: node.fingerprint || node.clientFingerprint || 'chrome',
        sni: node.sni || node.server,
        ...(includeEncryption ? { encryption: 'none' } : {}),
    });
    if (node.skipCertVerify) {
        query.set('insecure', '1');
        query.set('allowInsecure', '1');
    }
    if (node.network === 'ws' || node.network === 'xhttp') query.set('path', node.wsPath || node.xhttpPath || CLOUDFLARE_PATH);
    if (node.network === 'xhttp') query.set('mode', node.xhttpMode || 'stream-one');
    if (node.network === 'grpc') {
        query.set('serviceName', node.grpcServiceName || 'tunnel');
        query.set('mode', 'gun');
    }
    return query;
}

function buildShareLink(node) {
    if (node.shareLink) return node.shareLink;
    if (node.type === 'vless') {
        return `vless://${encodeURIComponent(node.uuid)}@${formatAuthority(node.server, node.port)}?${linkQuery(node, true)}#${encodeURIComponent(node.name)}`;
    }
    if (node.type === 'trojan') {
        return `trojan://${encodeURIComponent(node.password)}@${formatAuthority(node.server, node.port)}?${linkQuery(node)}#${encodeURIComponent(node.name)}`;
    }
    if (node.type === 'ss' || node.type === 'shadowsocks') {
        const credentials = base64(`${node.method || node.cipher || 'aes-128-gcm'}:${node.password}`);
        const pluginParts = [
            `mode=${node.pluginMode || 'websocket'}`,
            `host=${node.pluginHost || node.server}`,
            `path=${node.pluginPath || '/'}`,
        ];
        if (node.pluginTls) pluginParts.push('tls');
        if (node.pluginMux === false) pluginParts.push('mux=0');
        return `ss://${credentials}@${formatAuthority(node.server, node.port)}?${new URLSearchParams({ plugin: `${node.plugin || 'v2ray-plugin'};${pluginParts.join(';')}` })}#${encodeURIComponent(node.name)}`;
    }
    if (node.type === 'hysteria2') {
        const query = new URLSearchParams();
        if (node.skipCertVerify) query.set('insecure', '1');
        if (node.sni) query.set('sni', node.sni);
        return `hysteria2://${encodeURIComponent(node.password)}@${formatAuthority(node.server, node.port)}/?${query}#${encodeURIComponent(node.name)}`;
    }
    if (node.type === 'mieru') {
        const query = new URLSearchParams({
            'handshake-mode': node.handshakeMode || 'HANDSHAKE_STANDARD',
            mtu: String(node.mtu || 1400),
            multiplexing: node.multiplexing || 'MULTIPLEXING_HIGH',
            port: String(node.port),
            profile: node.profile || node.name,
            protocol: node.transport || 'TCP',
        });
        return `mierus://${encodeURIComponent(node.username)}:${encodeURIComponent(node.password)}@${node.server}?${query}#${encodeURIComponent(node.name)}`;
    }
    throw new Error(`Missing shareLink for unsupported node type: ${node.type}`);
}

function renderLogin(error = '', status = 200) {
    return response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Subscription</title><h1>Proxy Subscription</h1>${error ? `<p>${escapeHtml(error)}</p>` : ''}<form method="post"><label>Password <input name="password" type="password" required autofocus></label><button>Show subscription URL</button></form>`, status, { 'content-type': 'text/html; charset=utf-8' });
}

function renderSubscription(origin, config) {
    const clashUrl = `${origin}${config.paths.clash}`;
    const linksUrl = `${origin}${config.paths.links}`;
    return response(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Proxy Subscriptions</title><h1>Proxy Subscriptions</h1><p>Clash/Mihomo</p><p><a href="${escapeHtml(clashUrl)}">${escapeHtml(clashUrl)}</a></p><p>Share links</p><p><a href="${escapeHtml(linksUrl)}">${escapeHtml(linksUrl)}</a></p>`, 200, { 'content-type': 'text/html; charset=utf-8' });
}

async function readForm(request) {
    const contentType = request.headers.get('content-type') || '';
    if (!contentType.includes('application/x-www-form-urlencoded')) return new URLSearchParams();
    return new URLSearchParams(await request.text());
}

export default {
    async fetch(request, env) {
        let config;
        try {
            config = loadConfig(env);
        } catch (error) {
            return response(`Worker configuration error: ${error.message}\n`, 500, { 'content-type': 'text/plain; charset=utf-8' });
        }

        const url = new URL(request.url);
        if (url.pathname === '/' && request.method === 'GET') return renderLogin();
        if (url.pathname === '/' && request.method === 'POST') {
            const form = await readForm(request);
            return safeEqual(form.get('password'), config.pagePassword)
                ? renderSubscription(url.origin, config)
                : renderLogin('密码不正确', 401);
        }
        if (request.method !== 'GET' && request.method !== 'HEAD') return response('404 Not Found\n', 404, { 'content-type': 'text/plain; charset=utf-8' });

        const authorizedByPath = Object.values(config.paths).includes(url.pathname);
        const authorizedByQuery = safeEqual(url.searchParams.get('token'), config.token);
        if (!authorizedByPath && !authorizedByQuery) return response('404 Not Found\n', 404, { 'content-type': 'text/plain; charset=utf-8' });

        if (url.pathname === config.paths.links) {
            const links = `${config.nodes.map(buildShareLink).join('\n')}\n`;
            return textResponse(links, 'text/plain; charset=utf-8', 'cloudflare-links.txt', request.method === 'HEAD');
        }
        return textResponse(generateClashConfig(config.nodes), 'text/yaml; charset=utf-8', 'cloudflare-clash.yaml', request.method === 'HEAD');
    },
};
