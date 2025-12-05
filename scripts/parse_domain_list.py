#!/usr/bin/env python3
"""解析 v2fly/domain-list-community 格式的域名列表

支持的格式：
- 纯域名: domain.com (域名后缀匹配)
- full: full:domain.com (精确匹配)
- include: include:other-list (引用其他列表)
- regexp: regexp:正则表达式
- @tag: domain.com @cn (标记，如 @cn 表示中国可用)
- # 注释
"""
import json
from pathlib import Path
from typing import Dict, List, Optional, Set


# 双维度分类定义
# group: "type" = 按服务类型分类（包含所有地区）
# group: "region" = 按地区分类（该地区所有服务）

CATEGORIES = {
    # ==========================================
    # 按服务类型分类 (group: type)
    # ==========================================

    # ============ 流媒体 ============
    "streaming": {
        "name": "流媒体",
        "description": "Netflix, YouTube, Bilibili, Abema 等视频音频流媒体服务",
        "group": "type",
        "lists": [
            # 美国
            "netflix", "hulu", "disney", "hbo", "primevideo", "peacock",
            "apple-tvplus", "paramount", "amc", "discoveryplus", "pbs",
            "sling", "roku", "attwatchtv", "showtimeanytime", "plutotv",
            "cbs", "espn", "fox", "boomerang", "bamtech", "sonypictures",
            "wwe", "starplus", "c-span",
            # 日本
            "abema", "dmm", "niconico", "tver", "dazn", "bandai",
            "anime", "bahamut", "dlsite", "pixiv", "fansta",
            "tokyo-sports", "suruga-ya", "asahi", "sankei", "yomiuri",
            # 全球
            "youtube", "spotify", "twitch", "tiktok", "vimeo",
            "dailymotion", "soundcloud", "bandcamp", "tidal",
            "lastfm", "pocketcasts", "rumble", "streamable", "tubi",
            "viu", "zee", "zeetv", "catchplay", "vk", "rutube",
            # 中国
            "bilibili", "bilibili-cdn", "bilibili2", "iqiyi", "youku", "youku-ads",
            "sohu", "pptv", "douyin", "kuaishou", "ximalaya", "ximalaya-ads",
            "kugou", "kuwo", "netease", "douyu", "huya", "acfun",
            "bestv", "mgtv", "wasu", "fengxing"
        ],
        "recommended_exit": "direct"
    },

    # ============ 游戏 ============
    "gaming": {
        "name": "游戏",
        "description": "Steam, Epic, PlayStation, 原神, LOL 等游戏平台和服务",
        "group": "type",
        "lists": [
            # 国际
            "steam", "steamunlocked", "epicgames", "playstation", "xbox", "nintendo",
            "blizzard", "riot", "ea", "ubisoft", "gog", "rockstar",
            "2kgames", "bethesda", "wbgames", "supercell", "roblox",
            "origin", "curseforge", "modrinth", "escapefromtarkov",
            "category-games", "category-games-!cn", "category-game-platforms-download",
            "category-enhance-gaming", "trackernetwork",
            # 日本
            "cygames", "hoyoverse", "mihoyo", "nexon",
            "nikke", "bluearchive", "projectsekai", "snk", "garena",
            "visualarts", "asobo", "bluepoch", "bluepoch-games", "erolabs",
            # 中国
            "tencent-games", "bilibili-game",
            "category-games-cn", "category-game-accelerator-cn",
            "mihoyo-cn", "4399", "37games", "seasun", "tiancity",
            "duowan", "tgbus", "xiaoheihe"
        ],
        "recommended_exit": "game-exit"
    },

    # ============ 社交媒体 ============
    "social": {
        "name": "社交媒体",
        "description": "Twitter, Facebook, 微信, 微博等社交平台",
        "group": "type",
        "lists": [
            # 国际
            "twitter", "x", "facebook", "facebook-dev", "instagram", "discord",
            "telegram", "whatsapp", "whatsapp-ads", "reddit", "linkedin", "threads",
            "clubhouse", "messenger", "signal", "line", "viber",
            "tumblr", "pinterest", "mastodon", "bluesky", "fandom",
            "category-social-media-!cn",
            # 中国
            "weibo", "xiaohongshu", "douban", "renren",
            "zhihu", "momo", "dingtalk", "feishu", "tencent",
            "category-social-media-cn", "tieba", "hupu"
        ],
        "recommended_exit": "direct"
    },

    # ============ AI服务 ============
    "ai": {
        "name": "AI 服务",
        "description": "OpenAI, Claude, 通义千问, 文心一言等 AI 服务",
        "group": "type",
        "lists": [
            # 国际
            "openai", "anthropic", "google-gemini", "google-deepmind",
            "perplexity", "huggingface", "groq", "cursor", "poe",
            "elevenlabs", "xai", "cerebras", "comfy", "comfy-ui-launcher",
            "category-ai-!cn", "category-ai-chat-!cn", "bytedance-ai-!cn",
            "apple-intelligence",
            # 中国
            "category-ai-cn", "doubao", "deepseek", "iflytek"
        ],
        "recommended_exit": "us-stream"
    },

    # ============ 开发者工具 ============
    "developer": {
        "name": "开发者工具",
        "description": "GitHub, GitLab, npm, Docker, JetBrains 等开发工具",
        "group": "type",
        "lists": [
            "github", "gitlab", "gitee", "docker", "npm",
            "jetbrains", "jetbrains-ai", "code", "atlassian", "trello",
            "stackexchange", "hashicorp", "kubernetes", "vercel",
            "golang", "rust", "python", "nodejs", "ruby", "dart", "scala",
            "maven", "gradle", "homebrew", "archlinux", "debian", "fedora",
            "ubuntu", "ubuntukylin", "redhat", "centos", "termux",
            "codeberg", "sourcehut", "sourceforge", "codeforces", "codecademy",
            "category-dev", "category-dev-cn", "category-container",
            "apifox", "apipost", "coding", "electron", "v8", "tex",
            "readthedocs", "sentry", "contentful"
        ],
        "recommended_exit": "direct"
    },

    # ============ 云服务 ============
    "cloud": {
        "name": "云服务",
        "description": "AWS, Azure, 阿里云, 腾讯云等云服务商",
        "group": "type",
        "lists": [
            # 国际
            "aws", "aws-cn", "google", "microsoft", "azure",
            "cloudflare", "cloudflare-cn", "cloudflare-ipfs", "digitalocean", "vultr",
            "oracle", "ibm", "akamai", "fastly", "cdn77", "stackpath",
            "linode", "hetzner", "ovh", "anexia", "cloudcone",
            "category-ddns", "category-doh",
            # 中国
            "alibaba", "alibabacloud", "aliyun", "aliyun-drive",
            "tencent", "qcloud", "huaweicloud", "qingcloud",
            "ucloud", "volcengine", "qiniu", "upai", "wangsu",
            "capitalonline", "category-httpdns-cn"
        ],
        "recommended_exit": "direct"
    },

    # ============ 新闻媒体 ============
    "news": {
        "name": "新闻媒体",
        "description": "CNN, BBC, 新浪, 网易等新闻媒体",
        "group": "type",
        "lists": [
            # 国际
            "cnn", "bbc", "nytimes", "reuters", "bloomberg",
            "wsj", "economist", "ft", "theguardian", "thesun", "thetimes",
            "ap", "afp", "fox", "cnbc", "npr", "voanews",
            "aljazeera", "dw", "rferl", "abc", "cbs",
            "dailymail", "barrons", "dowjones", "thomsonreuters",
            "category-media", "category-tech-media", "9to5", "anandtech",
            "cnet", "techpowerup", "techtimes", "voxmedia", "theverge",
            # 中国
            "sina", "netease", "sohu", "ifeng", "chinanews",
            "cctv", "people", "xinhua", "chinadaily", "bjyouth",
            "36kr", "tmtpost", "cnbeta", "category-media-cn"
        ],
        "recommended_exit": "direct"
    },

    # ============ 电商购物 ============
    "ecommerce": {
        "name": "电商购物",
        "description": "Amazon, 淘宝, 京东等电商平台",
        "group": "type",
        "lists": [
            # 国际
            "amazon", "ebay", "shopify", "etsy", "walmart",
            "bestbuy", "target", "costco", "aliexpress", "wish",
            "rakuten", "coupang", "shopee", "farfetch", "category-ecommerce",
            # 中国
            "taobao", "jd", "pinduoduo", "suning", "dangdang",
            "meituan", "eleme", "ctrip", "didi", "dewu",
            "smzdm", "bestore", "vancl", "vip"
        ],
        "recommended_exit": "direct"
    },

    # ============ 通讯工具 ============
    "communication": {
        "name": "通讯工具",
        "description": "Zoom, Slack, Teams, Skype 等通讯工具",
        "group": "type",
        "lists": [
            "zoom", "slack", "webex", "skype",
            "viber", "line", "kakao", "teamviewer",
            "category-communication", "category-voip", "talkatone"
        ],
        "recommended_exit": "direct"
    },

    # ============ 加密货币 ============
    "cryptocurrency": {
        "name": "加密货币",
        "description": "Binance, Coinbase, OKX 等加密货币交易所",
        "group": "type",
        "lists": [
            "binance", "okx", "bybit", "bitflyer", "coinone",
            "gateio", "huobi", "category-cryptocurrency",
            "ethereum", "trustwallet", "bitsquare", "8btc"
        ],
        "recommended_exit": "direct"
    },

    # ============ VPN/代理 ============
    "vpn-proxy": {
        "name": "VPN/代理",
        "description": "各类 VPN 和代理服务",
        "group": "type",
        "lists": [
            "category-vpnservices", "category-anticensorship",
            "v2ray", "torproject", "tor", "vpngate",
            "shadowsockscom", "softether", "tailscale",
            "squirrelvpn", "vilavpn", "dlercloud", "boslife", "ssrcloud"
        ],
        "recommended_exit": "direct"
    },

    # ============ 学术研究 ============
    "scholar": {
        "name": "学术研究",
        "description": "Google Scholar, arXiv, IEEE, 知网等学术资源",
        "group": "type",
        "lists": [
            "google-scholar", "category-scholar-!cn", "category-scholar-cn",
            "ieee", "springer", "elsevier", "clarivate", "sciencedirect",
            "sci-hub", "libgen", "annas-archive", "z-library",
            "doi", "cern", "embl", "arxiv", "taylorfrancis", "cnki"
        ],
        "recommended_exit": "direct"
    },

    # ============ 教育学习 ============
    "education": {
        "name": "教育学习",
        "description": "Coursera, Udemy, 学而思等在线教育平台",
        "group": "type",
        "lists": [
            "coursera", "udemy", "udacity", "edx", "codecademy",
            "duolingo", "duolingo-ads", "egghead", "skillshare", "brilliant",
            "chegg", "category-mooc-cn", "category-education-cn",
            "xueersi", "yuanfudao", "zuoyebang", "17zuoye", "yuketang"
        ],
        "recommended_exit": "direct"
    },

    # ============ PT/BT ============
    "pt-tracker": {
        "name": "PT/BT 站点",
        "description": "各类 PT 站和 BT Tracker",
        "group": "type",
        "lists": [
            "category-pt", "category-public-tracker",
            "piratebay", "nyaa", "1337x", "rarbg",
            "btdig", "rutracker", "tokyo-toshokan", "demonoid"
        ],
        "recommended_exit": "direct"
    },

    # ============ ACG 动漫 ============
    "acg": {
        "name": "ACG 动漫",
        "description": "动画、漫画、轻小说等二次元内容",
        "group": "type",
        "lists": [
            "category-acg", "anime", "bangumi", "ehentai",
            "copymanga", "18comic", "acplay", "dandanzan",
            "boylove", "archiveofourown", "2ch", "4chan", "5ch",
            "ck101", "stage1st"
        ],
        "recommended_exit": "direct"
    },

    # ============ 小说阅读 ============
    "novel": {
        "name": "小说阅读",
        "description": "起点、晋江等网络文学平台",
        "group": "type",
        "lists": [
            "category-novel", "yuewen", "ciweimao", "qimao",
            "webnovel", "books"
        ],
        "recommended_exit": "direct"
    },

    # ============ 成人内容 ============
    "adult": {
        "name": "成人内容",
        "description": "成人网站 (NSFW)",
        "group": "type",
        "lists": [
            "category-porn", "pornhub", "xvideos", "xhamster",
            "xnxx", "youporn", "redtube", "tube8", "javbus", "javdb",
            "dmm-porn", "brazzers", "digitalplayground", "realitykings",
            "bongacams", "chaturbate", "camwhores", "spankbang",
            "clips4sale", "awempire", "boboporn", "cavporn",
            "coomer", "theporndude", "truyen-hentai", "sehuatang",
            "avmoo", "bdsmhub", "youjizz"
        ],
        "recommended_exit": "direct"
    },

    # ============ 广告服务 ============
    "advertising": {
        "name": "广告服务",
        "description": "各类广告和追踪服务 (可用于屏蔽)",
        "group": "type",
        "lists": [
            "category-ads", "category-ads-all", "google-ads",
            "facebook-ads", "amazon-ads", "baidu-ads",
            "bytedance-ads", "tencent-ads", "alibaba-ads",
            "apple-ads", "acfun-ads", "dmm-ads", "sina-ads", "sohu-ads",
            "unity-ads", "spotify-ads", "xiaomi-ads",
            "adjust-ads", "applovin-ads", "adcolony-ads",
            "clearbit-ads", "segment-ads", "sensorsdata-ads", "taboola",
            "supersonic-ads", "tappx-ads", "television-ads", "atom-data-ads",
            "emogi-ads", "umeng-ads", "xhamster-ads", "uberads-ads", "tagtic-ads",
            "category-ads-ir"
        ],
        "recommended_exit": "block"
    },

    # ============ 网盘存储 ============
    "cloud-storage": {
        "name": "网盘存储",
        "description": "Dropbox, Google Drive, 百度网盘等云存储服务",
        "group": "type",
        "lists": [
            "dropbox", "box", "mega", "mediafire", "category-netdisk-cn",
            "terabox", "cowtransfer", "wenshushu", "aliyun-drive",
            "115", "xunlei"
        ],
        "recommended_exit": "direct"
    },

    # ============ 科技公司 ============
    "tech-companies": {
        "name": "科技公司",
        "description": "Apple, Microsoft, Google, 华为, 小米等科技公司",
        "group": "type",
        "lists": [
            "apple", "apple-dev", "apple-update", "apple-pki",
            "microsoft", "microsoft-dev", "microsoft-pki",
            "google", "google-play", "google-registry", "google-trust-services", "googlefcm",
            "amazon", "amazontrust", "meta",
            "nvidia", "intel", "amd", "qualcomm", "samsung",
            "huawei", "xiaomi", "oppo", "vivo", "lenovo", "asus",
            "dell", "acer", "sony", "canon", "cisco",
            "broadcom", "vmware", "adobe", "autodesk", "corel",
            "symantec", "eset", "drweb", "category-antivirus"
        ],
        "recommended_exit": "direct"
    },

    # ============ 金融服务 ============
    "finance": {
        "name": "金融服务",
        "description": "银行、证券、支付等金融服务",
        "group": "type",
        "lists": [
            "paypal", "visa", "mastercard", "stripe", "squareup", "wise",
            "category-bank-cn", "category-securities-cn", "category-finance",
            "unionpay", "alipay", "schwab", "eastmoney", "xueqiu",
            "category-bank-jp", "category-bank-ir", "category-bank-mm"
        ],
        "recommended_exit": "direct"
    },

    # ============ 物流快递 ============
    "logistics": {
        "name": "物流快递",
        "description": "顺丰、圆通、FedEx 等物流服务",
        "group": "type",
        "lists": [
            "category-logistics-cn", "sf-express", "yto-express",
            "zto-express", "sto-express", "yundaex", "800best",
            "deppon", "cainiao", "fcbox"
        ],
        "recommended_exit": "direct"
    },

    # ============ 汽车服务 ============
    "automotive": {
        "name": "汽车服务",
        "description": "Tesla, BMW, 懂车帝等汽车服务",
        "group": "type",
        "lists": [
            "tesla", "bmw", "volvo", "category-automobile-cn",
            "bitauto", "dongchedi", "amap"
        ],
        "recommended_exit": "direct"
    },

    # ============ 旅游出行 ============
    "travel": {
        "name": "旅游出行",
        "description": "Booking, 携程等旅游预订服务",
        "group": "type",
        "lists": [
            "booking", "airbnb", "tripadvisor",
            "ctrip", "tongcheng", "meituan"
        ],
        "recommended_exit": "direct"
    },

    # ============ 办公协作 ============
    "enterprise": {
        "name": "办公协作",
        "description": "Notion, 飞书, 钉钉等办公协作工具",
        "group": "type",
        "lists": [
            "category-collaborate-cn", "category-documents-cn",
            "feishu", "dingtalk", "teambition", "wolai",
            "notion", "figma", "canva", "evernote", "quip",
            "asana", "monday", "basecamp", "dropbox"
        ],
        "recommended_exit": "direct"
    },

    # ============ 网络工具 ============
    "network-tools": {
        "name": "网络工具",
        "description": "DNS, 测速, 远程控制等网络工具",
        "group": "type",
        "lists": [
            "category-doh", "cloudflare", "google",
            "dnspod", "zdns", "category-ntp", "category-ntp-cn", "category-ntp-jp",
            "category-speedtest", "speedtest", "category-ip-geo-detect",
            "test-ipv6", "connectivity-check",
            "category-remote-control", "teamviewer", "parsec",
            "anydesk", "sunlogin"
        ],
        "recommended_exit": "direct"
    },

    # ============ 安全隐私 ============
    "security": {
        "name": "安全隐私",
        "description": "证书、密码管理、隐私工具",
        "group": "type",
        "lists": [
            "digicert", "letsencrypt", "sectigo", "comodo", "entrust",
            "globalsign", "godaddy", "verisign", "verisign-pki", "symantec-pki",
            "apple-pki", "microsoft-pki", "google-trust-services",
            "actalis", "buypass", "certinomis", "certum", "cybertrust",
            "sslcom", "swisssign", "trustwave", "twca", "wisekey",
            "category-cas", "category-password-management", "bitwarden", "1password",
            "lastpass", "keepass", "protonmail", "tutanota",
            "duckduckgo", "startpage", "qwant", "epicbrowser",
            "adblock", "adblockplus", "adguard"
        ],
        "recommended_exit": "direct"
    },

    # ============ 设计创意 ============
    "design": {
        "name": "设计创意",
        "description": "Figma, Dribbble 等设计平台",
        "group": "type",
        "lists": [
            "figma", "dribbble", "behance", "artstation", "deviantart",
            "canva", "adobe", "sketch", "invision",
            "unsplash", "pexels", "shutterstock"
        ],
        "recommended_exit": "direct"
    },

    # ============ IPFS/Web3 ============
    "ipfs": {
        "name": "IPFS/Web3",
        "description": "IPFS 及去中心化存储",
        "group": "type",
        "lists": [
            "category-ipfs", "cloudflare-ipfs", "infura"
        ],
        "recommended_exit": "direct"
    },

    # ============ 论坛社区 ============
    "forums": {
        "name": "论坛社区",
        "description": "各类论坛和社区",
        "group": "type",
        "lists": [
            "category-forums", "discuz", "v2ex", "hostloc",
            "4chan", "4plebs", "2ch", "5ch", "reddit",
            "6park", "huaren", "mitbbs"
        ],
        "recommended_exit": "direct"
    },

    # ============ 媒体工具 ============
    "media-tools": {
        "name": "媒体工具",
        "description": "Emby, Plex 等媒体服务器",
        "group": "type",
        "lists": [
            "category-emby", "plex", "jellyfin", "kodi",
            "tmdb", "tvdb", "imdb", "rottentomatoes"
        ],
        "recommended_exit": "direct"
    },

    # ============ 短链服务 ============
    "url-shortener": {
        "name": "短链服务",
        "description": "bit.ly 等短链接服务",
        "group": "type",
        "lists": [
            "bitly", "tinyurl", "shorturl", "cuttly", "reurl", "rebrandly"
        ],
        "recommended_exit": "direct"
    },

    # ============ 百科知识 ============
    "wiki": {
        "name": "百科知识",
        "description": "维基百科等百科网站",
        "group": "type",
        "lists": [
            "wikimedia", "wikipedia", "wikihow", "wikidot",
            "category-wiki-cn", "baike"
        ],
        "recommended_exit": "direct"
    },

    # ============ 博客平台 ============
    "blogs": {
        "name": "博客平台",
        "description": "Medium, CSDN 等博客和写作平台",
        "group": "type",
        "lists": [
            "category-blog-cn", "medium", "substack", "wordpress",
            "blogspot", "csdn", "cnblogs", "jianshu", "segmentfault",
            "feedly", "inoreader", "rsshub", "rsshub-3rd"
        ],
        "recommended_exit": "direct"
    },

    # ============ 众筹支持 ============
    "crowdfunding": {
        "name": "众筹支持",
        "description": "Patreon, 爱发电等创作者支持平台",
        "group": "type",
        "lists": [
            "patreon", "afdian", "buymeacoffee", "kofi"
        ],
        "recommended_exit": "direct"
    },

    # ============ 安卓应用 ============
    "android-apps": {
        "name": "应用商店",
        "description": "应用商店和 APK 下载",
        "group": "type",
        "lists": [
            "category-android-app-download", "google-play",
            "apkpure", "apkmirror", "aptoide", "apkcombo",
            "coolapk", "android"
        ],
        "recommended_exit": "direct"
    },

    # ============ 天气服务 ============
    "weather": {
        "name": "天气服务",
        "description": "天气预报服务",
        "group": "type",
        "lists": [
            "accuweather", "weathercn", "qweather", "colorfulclouds", "windy"
        ],
        "recommended_exit": "direct"
    },

    # ============ 信息竞赛 ============
    "olympiad": {
        "name": "信息竞赛",
        "description": "信息学奥赛相关资源",
        "group": "type",
        "lists": [
            "category-olympiad-in-informatics", "codeforces",
            "leetcode", "topcoder", "hackerrank"
        ],
        "recommended_exit": "direct"
    },

    # ============ 组织机构 ============
    "organizations": {
        "name": "组织机构",
        "description": "各类国际组织和机构",
        "group": "type",
        "lists": [
            "category-orgs", "category-companies", "un", "nato",
            "who", "wto", "imf", "worldbank"
        ],
        "recommended_exit": "direct"
    }
}


class DomainListParser:
    def __init__(self, data_dir: Path):
        self.data_dir = data_dir
        self._cache: Dict[str, dict] = {}

    def parse_file(self, name: str, visited: Optional[Set[str]] = None) -> dict:
        """解析单个域名列表文件"""
        if visited is None:
            visited = set()

        if name in visited:
            return {"domains": [], "full_domains": [], "regexps": []}
        visited.add(name)

        if name in self._cache:
            return self._cache[name]

        file_path = self.data_dir / name
        if not file_path.exists():
            return {"domains": [], "full_domains": [], "regexps": []}

        domains: List[str] = []
        full_domains: List[str] = []
        regexps: List[str] = []
        includes: List[str] = []

        content = file_path.read_text(encoding="utf-8")
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # 移除 @tag 标记
            if " @" in line:
                line = line.split(" @")[0].strip()

            if line.startswith("include:"):
                includes.append(line[8:])
            elif line.startswith("full:"):
                full_domains.append(line[5:])
            elif line.startswith("regexp:"):
                regexps.append(line[7:])
            else:
                domains.append(line)

        # 递归处理 include
        for inc in includes:
            inc_data = self.parse_file(inc, visited)
            domains.extend(inc_data.get("domains", []))
            full_domains.extend(inc_data.get("full_domains", []))
            regexps.extend(inc_data.get("regexps", []))

        result = {
            "domains": list(set(domains)),
            "full_domains": list(set(full_domains)),
            "regexps": list(set(regexps)),
        }
        self._cache[name] = result
        return result

    def get_domain_suffixes(self, name: str) -> List[str]:
        """获取域名后缀列表（用于 sing-box rule_set）"""
        data = self.parse_file(name)
        return data.get("domains", [])

    def file_exists(self, name: str) -> bool:
        """检查文件是否存在"""
        return (self.data_dir / name).exists()


def build_catalog(data_dir: Path) -> dict:
    """构建域名列表目录"""
    parser = DomainListParser(data_dir)

    catalog = {"categories": {}, "lists": {}}

    # 第一遍：构建 list_id -> type_categories 映射
    list_to_types: Dict[str, List[str]] = {}
    type_categories = {k: v for k, v in CATEGORIES.items() if v.get("group") == "type"}

    for cat_id, cat_info in type_categories.items():
        for list_name in cat_info["lists"]:
            if list_name not in list_to_types:
                list_to_types[list_name] = []
            list_to_types[list_name].append(cat_id)

    for cat_id, cat_info in CATEGORIES.items():
        cat_lists = []
        for list_name in cat_info["lists"]:
            if parser.file_exists(list_name):
                domains = parser.get_domain_suffixes(list_name)
                list_data = {
                    "id": list_name,
                    "domain_count": len(domains),
                    "sample_domains": domains[:10] if domains else []
                }
                cat_lists.append(list_data)

                # 存储完整域名列表
                catalog["lists"][list_name] = {
                    "domains": domains,
                    "full_domains": parser.parse_file(list_name).get("full_domains", [])
                }

        if cat_lists:  # 只添加有列表的分类
            category_data = {
                "name": cat_info["name"],
                "description": cat_info["description"],
                "group": cat_info.get("group", "type"),
                "recommended_exit": cat_info["recommended_exit"],
                "lists": cat_lists
            }

            # 为地区分类添加类型分布统计
            if cat_info.get("group") == "region":
                type_breakdown = {}
                for list_item in cat_lists:
                    list_id = list_item["id"]
                    for type_cat_id in list_to_types.get(list_id, []):
                        if type_cat_id not in type_breakdown:
                            type_info = type_categories[type_cat_id]
                            type_breakdown[type_cat_id] = {
                                "name": type_info["name"],
                                "count": 0,
                                "lists": []
                            }
                        type_breakdown[type_cat_id]["count"] += 1
                        type_breakdown[type_cat_id]["lists"].append(list_id)

                # 按数量排序
                sorted_breakdown = dict(sorted(
                    type_breakdown.items(),
                    key=lambda x: x[1]["count"],
                    reverse=True
                ))
                category_data["type_breakdown"] = sorted_breakdown

            catalog["categories"][cat_id] = category_data

    return catalog


if __name__ == "__main__":
    import sys

    data_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("/etc/sing-box/domain-list/data")
    output_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("/etc/sing-box/domain-catalog.json")

    if not data_dir.exists():
        print(f"域名列表目录不存在: {data_dir}", file=sys.stderr)
        sys.exit(1)

    catalog = build_catalog(data_dir)
    output_path.write_text(json.dumps(catalog, indent=2, ensure_ascii=False))
    print(f"已生成域名目录: {output_path}")
    print(f"分类数量: {len(catalog['categories'])}")
    print(f"域名列表数量: {len(catalog['lists'])}")

    # 打印分类统计
    print("\n分类统计:")
    for cat_id, cat_info in catalog["categories"].items():
        print(f"  {cat_info['name']}: {len(cat_info['lists'])} 个列表")
