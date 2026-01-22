/*
powerfullz 的 Substore 订阅转换脚本 (已集成 BackHome 覆写)
https://github.com/powerfullz/override-rules
*/

const NODE_SUFFIX = "节点";

function parseBool(value) {
    if (typeof value === "boolean") return value;
    if (typeof value === "string") {
        return value.toLowerCase() === "true" || value === "1";
    }
    return false;
}

function parseNumber(value, defaultValue = 0) {
    if (value === null || typeof value === 'undefined') {
        return defaultValue;
    }
    const num = parseInt(value, 10);
    return isNaN(num) ? defaultValue : num;
}

function buildFeatureFlags(args) {
    const spec = {
        loadbalance: "loadBalance",
        landing: "landing",
        ipv6: "ipv6Enabled",
        full: "fullConfig",
        keepalive: "keepAliveEnabled",
        fakeip: "fakeIPEnabled",
        quic: "quicEnabled"
    };

    const flags = Object.entries(spec).reduce((acc, [sourceKey, targetKey]) => {
        acc[targetKey] = parseBool(args[sourceKey]) || false;
        return acc;
    }, {});

    flags.countryThreshold = parseNumber(args.threshold, 0);
    return flags;
}

const rawArgs = typeof $arguments !== 'undefined' ? $arguments : {};
const {
    loadBalance,
    landing,
    ipv6Enabled,
    fullConfig,
    keepAliveEnabled,
    fakeIPEnabled,
    quicEnabled,
    countryThreshold
} = buildFeatureFlags(rawArgs);

function getCountryGroupNames(countryInfo, minCount) {
    return countryInfo
        .filter(item => item.count >= minCount)
        .map(item => item.country + NODE_SUFFIX);
}

function stripNodeSuffix(groupNames) {
    const suffixPattern = new RegExp(`${NODE_SUFFIX}$`);
    return groupNames.map(name => name.replace(suffixPattern, ""));
}

const PROXY_GROUPS = {
    SELECT: "选择代理",
    MANUAL: "手动选择",
    FALLBACK: "故障转移",
    DIRECT: "直连",
    LANDING: "落地节点",
    LOW_COST: "低倍率节点",
    BACK_HOME: "BackHome", // 新增策略组常量
};

const buildList = (...elements) => elements.flat().filter(Boolean);

function buildBaseLists({ landing, lowCost, countryGroupNames }) {
    const defaultSelector = buildList(
        PROXY_GROUPS.FALLBACK,
        landing && PROXY_GROUPS.LANDING,
        countryGroupNames,
        lowCost && PROXY_GROUPS.LOW_COST,
        PROXY_GROUPS.MANUAL,
        "DIRECT"
    );

    const defaultProxies = buildList(
        PROXY_GROUPS.SELECT,
        countryGroupNames,
        lowCost && PROXY_GROUPS.LOW_COST,
        PROXY_GROUPS.MANUAL,
        PROXY_GROUPS.DIRECT
    );

    const defaultProxiesDirect = buildList(
        PROXY_GROUPS.DIRECT,
        countryGroupNames,
        lowCost && PROXY_GROUPS.LOW_COST,
        PROXY_GROUPS.SELECT,
        PROXY_GROUPS.MANUAL
    );

    const defaultFallback = buildList(
        landing && PROXY_GROUPS.LANDING,
        countryGroupNames,
        lowCost && PROXY_GROUPS.LOW_COST,
        PROXY_GROUPS.MANUAL,
        "DIRECT"
    );

    return { defaultProxies, defaultProxiesDirect, defaultSelector, defaultFallback };
}

const ruleProviders = {
    "ADBlock": {
        "type": "http",
        "behavior": "domain",
        "format": "mrs",
        "interval": 86400,
        "url": "https://adrules.top/adrules-mihomo.mrs",
        "path": "./ruleset/ADBlock.mrs"
    },
    // ... 其他 ruleProviders 保持不变
    "SogouInput": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://ruleset.skk.moe/Clash/non_ip/sogouinput.txt", "path": "./ruleset/SogouInput.txt" },
    "StaticResources": { "type": "http", "behavior": "domain", "format": "text", "interval": 86400, "url": "https://ruleset.skk.moe/Clash/domainset/cdn.txt", "path": "./ruleset/StaticResources.txt" },
    "CDNResources": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://ruleset.skk.moe/Clash/non_ip/cdn.txt", "path": "./ruleset/CDNResources.txt" },
    "TikTok": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/TikTok.list", "path": "./ruleset/TikTok.list" },
    "EHentai": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/EHentai.list", "path": "./ruleset/EHentai.list" },
    "SteamFix": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/SteamFix.list", "path": "./ruleset/SteamFix.list" },
    "GoogleFCM": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/FirebaseCloudMessaging.list", "path": "./ruleset/FirebaseCloudMessaging.list" },
    "AdditionalFilter": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalFilter.list", "path": "./ruleset/AdditionalFilter.list" },
    "AdditionalCDNResources": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/AdditionalCDNResources.list", "path": "./ruleset/AdditionalCDNResources.list" },
    "Crypto": { "type": "http", "behavior": "classical", "format": "text", "interval": 86400, "url": "https://gcore.jsdelivr.net/gh/powerfullz/override-rules@master/ruleset/Crypto.list", "path": "./ruleset/Crypto.list" }
}

const baseRules = [
    `IP-CIDR,192.168.50.0/24,${PROXY_GROUPS.BACK_HOME},no-resolve`, // 新增：BackHome IP 规则置顶
    `RULE-SET,ADBlock,广告拦截`,
    `RULE-SET,AdditionalFilter,广告拦截`,
    `RULE-SET,SogouInput,搜狗输入法`,
    `DOMAIN-SUFFIX,truthsocial.com,Truth Social`,
    `RULE-SET,StaticResources,静态资源`,
    `RULE-SET,CDNResources,静态资源`,
    `RULE-SET,AdditionalCDNResources,静态资源`,
    `RULE-SET,Crypto,Crypto`,
    `RULE-SET,EHentai,E-Hentai`,
    `RULE-SET,TikTok,TikTok`,
    `RULE-SET,SteamFix,${PROXY_GROUPS.DIRECT}`,
    `RULE-SET,GoogleFCM,${PROXY_GROUPS.DIRECT}`,
    `DOMAIN,services.googleapis.cn,${PROXY_GROUPS.SELECT}`,
    "GEOSITE,CATEGORY-AI-!CN,AI",
    `GEOSITE,GOOGLE-PLAY@CN,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,MICROSOFT@CN,${PROXY_GROUPS.DIRECT}`,
    "GEOSITE,ONEDRIVE,OneDrive",
    "GEOSITE,MICROSOFT,Microsoft",
    "GEOSITE,TELEGRAM,Telegram",
    "GEOSITE,YOUTUBE,YouTube",
    "GEOSITE,GOOGLE,Google",
    "GEOSITE,NETFLIX,Netflix",
    "GEOSITE,SPOTIFY,Spotify",
    "GEOSITE,BAHAMUT,Bahamut",
    "GEOSITE,BILIBILI,Bilibili",
    "GEOSITE,PIKPAK,PikPak",
    `GEOSITE,GFW,${PROXY_GROUPS.SELECT}`,
    `GEOSITE,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOSITE,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    "GEOIP,NETFLIX,Netflix,no-resolve",
    "GEOIP,TELEGRAM,Telegram,no-resolve",
    `GEOIP,CN,${PROXY_GROUPS.DIRECT}`,
    `GEOIP,PRIVATE,${PROXY_GROUPS.DIRECT}`,
    "DST-PORT,22,SSH(22端口)",
    `MATCH,${PROXY_GROUPS.SELECT}`
];

function buildRules({ quicEnabled }) {
    const ruleList = [...baseRules];
    if (!quicEnabled) {
        ruleList.unshift("AND,((DST
