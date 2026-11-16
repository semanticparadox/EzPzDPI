package main

// catalog lists the services EzPzDPI checks, from research verified on
// 2026-11-16 (sources in docs/research). Expected sizes come from US
// baselines; a body that stalls far below them is throttling.
var catalog = []Service{
	// --- video and music ---
	{
		ID: "youtube", Name: "YouTube", Category: "video", Default: true,
		Targets: []Target{
			{Host: "www.youtube.com", Path: "/generate_204"},
			{Host: "www.youtube.com", Path: "/", MinBytes: 256 << 10},
			{Host: "i.ytimg.com", Path: "/vi/dQw4w9WgXcQ/default.jpg", MinBytes: 2500},
			{Host: "redirector.googlevideo.com", Path: "/report_mapping", MinBytes: 256 << 10},
		},
		Note: "Если сайт открывается, а видео зависает, отключите QUIC в браузере (chrome://flags/#enable-quic) и блокировщик рекламы.",
	},
	{
		ID: "twitch", Name: "Twitch", Category: "video", Default: true, NoBypass: true,
		Targets: []Target{
			{Host: "www.twitch.tv", Path: "/", MinBytes: 64 << 10},
			{Host: "gql.twitch.tv", Path: "/"},
			{Host: "usher.ttvnw.net", Path: "/"},
		},
		Note: "Набор Flowseal намеренно не пропускает Twitch через обход: так он ломается реже.",
	},
	{
		ID: "tiktok", Name: "TikTok", Category: "video", Default: true,
		Targets: []Target{{Host: "www.tiktok.com", Path: "/"}},
		Domains: []string{"tiktok.com", "tiktokv.com", "tiktokcdn.com", "byteoversea.com", "ibytedtos.com", "muscdn.com", "ttwstatic.com"},
	},
	{
		ID: "soundcloud", Name: "SoundCloud", Category: "video",
		Targets: []Target{{Host: "soundcloud.com", Path: "/"}},
		Domains: []string{"soundcloud.com", "sndcdn.com"},
	},
	{
		ID: "spotify", Name: "Spotify", Category: "video", ProviderGeo: true,
		Targets: []Target{{Host: "open.spotify.com", Path: "/"}},
		Advice:  "Spotify сам ограничил пользователей из России: нужен зарубежный адрес (VPN), а для оплаты зарубежный аккаунт.",
	},
	// --- social ---
	{
		ID: "meta", Name: "Instagram и Facebook", Category: "social", Default: true,
		Targets: []Target{
			{Host: "www.instagram.com", Path: "/", MinBytes: 128 << 10},
			{Host: "www.facebook.com", Path: "/", MinBytes: 128 << 10},
			{Host: "scontent.cdninstagram.com", Path: "/"},
		},
		Domains: []string{"instagram.com", "cdninstagram.com", "ig.me", "facebook.com", "fb.com", "fbcdn.net", "fbsbx.com", "facebook.net", "messenger.com", "threads.net", "threads.com"},
		Advice:  "Если обход не помог, нужен VPN.",
	},
	{
		ID: "x", Name: "X (Twitter)", Category: "social", Default: true,
		Targets: []Target{
			{Host: "x.com", Path: "/", MinBytes: 32 << 10},
			{Host: "abs.twimg.com", Path: "/"},
		},
		Domains: []string{"x.com", "twitter.com", "t.co", "twimg.com", "twttr.com", "ads-twitter.com", "pscp.tv", "periscope.tv"},
		Advice:  "Если обход не помог, нужен VPN.",
	},
	{
		ID: "linkedin", Name: "LinkedIn", Category: "social",
		Targets: []Target{{Host: "www.linkedin.com", Path: "/"}},
		Domains: []string{"linkedin.com", "licdn.com"},
	},
	// --- messengers and calls ---
	{
		ID: "telegram", Name: "Telegram", Category: "messenger", Default: true,
		Targets: []Target{
			{Host: "telegram.org", Path: "/", MinBytes: 16 << 10},
			{Host: "web.telegram.org", Path: "/", MinBytes: 1 << 10},
			{Host: "t.me", Path: "/telegram", MinBytes: 8 << 10},
			{Host: "149.154.167.220", Path: "", TCPOnly: true},
		},
		Domains: []string{"telegram.org", "t.me", "telegram.me", "telesco.pe", "cdn-telegram.org", "telegra.ph", "tdesktop.com"},
		Known:   "Звонки в Telegram блокируются с августа 2025 года.",
		Note:    "Приложение Telegram соединяется со своими серверами без имени сайта, поэтому обход помогает ему не всегда.",
	},
	{
		ID: "whatsapp", Name: "WhatsApp", Category: "messenger", Default: true,
		Targets: []Target{
			{Host: "web.whatsapp.com", Path: "/", MinBytes: 16 << 10},
			{Host: "www.whatsapp.com", Path: "/"},
			{Host: "static.whatsapp.net", Path: "/"},
		},
		Domains: []string{"whatsapp.com", "whatsapp.net", "wa.me"},
		Known:   "Звонки в WhatsApp блокируются с августа 2025 года.",
	},
	{
		ID: "discord", Name: "Discord", Category: "messenger", Default: true,
		Targets: []Target{
			{Host: "discord.com", Path: "/api/v10/gateway", MinBytes: 20},
			{Host: "discord.com", Path: "/", MinBytes: 64 << 10},
			{Host: "cdn.discordapp.com", Path: "/embed/avatars/0.png", MinBytes: 1000},
			{Host: "gateway.discord.gg", Path: "/"},
		},
		Domains: []string{"discord.com", "discord.gg", "discord.media", "discordapp.com", "discordapp.net", "discordcdn.com", "discord.gift", "discord.gifts", "dis.gd"},
		Note:    "Голосовые каналы автоматически не проверяются. Если голос обрывается, смотрите строку «Звонки и голос».",
	},
	{
		ID: "voice", Name: "Звонки и голос", Category: "messenger", Default: true, Special: "voice",
		Note: "Проверка отправляет UDP-запросы STUN, как при звонках. Сам звонок проверить нельзя: после включения обхода позвоните, чтобы убедиться.",
	},
	{
		ID: "signal", Name: "Signal", Category: "messenger",
		Targets: []Target{{Host: "signal.org", Path: "/"}},
		Domains: []string{"signal.org", "whispersystems.org", "signal.art"},
		Known:   "Проверяется только сайт: само приложение может не работать.",
	},
	{
		ID: "viber", Name: "Viber", Category: "messenger",
		Targets: []Target{{Host: "www.viber.com", Path: "/"}},
		Domains: []string{"viber.com"},
	},
	{
		ID: "meet", Name: "Google Meet", Category: "messenger",
		Targets: []Target{{Host: "meet.google.com", Path: "/"}},
		Note:    "Проверяется сайт. Качество звонка автоматически не проверить.",
	},
	{
		ID: "zoom", Name: "Zoom", Category: "messenger",
		Targets: []Target{{Host: "zoom.us", Path: "/"}},
	},
	// --- games ---
	{
		ID: "roblox", Name: "Roblox", Category: "games", Default: true,
		Targets: []Target{{Host: "www.roblox.com", Path: "/", MinBytes: 64 << 10}},
		Domains: []string{"roblox.com", "rbxcdn.com", "robloxdev.com", "rbxinfra.net"},
		Note:    "Не заходите в Roblox через VPN: по сообщениям СМИ, за подмену местоположения блокируют аккаунты.",
	},
	{
		ID: "steam", Name: "Steam", Category: "games", Default: true, NoBypass: true,
		Targets: []Target{
			{Host: "steamcommunity.com", Path: "/", MinBytes: 16 << 10},
			{Host: "store.steampowered.com", Path: "/"},
		},
		Note: "Набор Flowseal намеренно не пропускает Steam через обход.",
	},
	{
		ID: "faceit", Name: "FACEIT", Category: "games", Default: true,
		Targets: []Target{{Host: "www.faceit.com", Path: "/"}},
		Domains: []string{"faceit.com", "faceit-cdn.net"},
		Note:    "Игровые серверы и античит проверить нельзя. Античит может ругаться на драйвер обхода, поэтому игровой режим включайте осторожно.",
	},
	{
		ID: "epic", Name: "Epic Games", Category: "games", NoBypass: true,
		Targets: []Target{{Host: "store.epicgames.com", Path: "/"}},
	},
	{
		ID: "battlenet", Name: "Battle.net", Category: "games",
		Targets: []Target{{Host: "www.blizzard.com", Path: "/"}},
		Note:    "Игровые серверы этой проверкой не охватываются.",
	},
	// --- AI and work ---
	{
		ID: "chatgpt", Name: "ChatGPT", Category: "ai", Default: true, ProviderGeo: true,
		Targets: []Target{
			{Host: "chatgpt.com", Path: "/cdn-cgi/trace", MinBytes: 100},
			{Host: "api.openai.com", Path: "/v1/models"},
		},
		GeoSigns: []string{"unsupported_country", "country, region, or territory not supported"},
		Advice:   "OpenAI сам не работает с Россией. Нужен зарубежный адрес (VPN), и аккаунт при этом могут заблокировать.",
	},
	{
		ID: "claude", Name: "Claude", Category: "ai", ProviderGeo: true,
		Targets: []Target{{Host: "claude.ai", Path: "/"}},
		Advice:  "Anthropic сам не работает с Россией, аккаунты из России блокируют.",
	},
	{
		ID: "gemini", Name: "Gemini", Category: "ai", ProviderGeo: true,
		Targets: []Target{{Host: "gemini.google.com", Path: "/"}},
		Advice:  "Google сам не открывает Gemini для России.",
	},
	{
		ID: "github", Name: "GitHub", Category: "ai",
		Targets: []Target{{Host: "github.com", Path: "/"}, {Host: "api.github.com", Path: "/"}},
	},
	{
		ID: "pypi", Name: "PyPI", Category: "ai",
		Targets: []Target{{Host: "pypi.org", Path: "/simple/", MinBytes: 64 << 10}, {Host: "files.pythonhosted.org", Path: "/"}},
		Domains: []string{"pypi.org", "pythonhosted.org"},
	},
	{
		ID: "docker", Name: "Docker Hub", Category: "ai", ProviderGeo: true,
		Targets:  []Target{{Host: "registry-1.docker.io", Path: "/v2/"}},
		GeoCodes: []int{403},
		Advice:   "Docker Hub сам отказывает российским адресам. Используйте зеркало реестра.",
	},
	{
		ID: "notion", Name: "Notion", Category: "ai", ProviderGeo: true,
		Targets: []Target{{Host: "www.notion.so", Path: "/"}},
		Advice:  "Notion сам блокирует аккаунты из России.",
	},
	{
		ID: "figma", Name: "Figma", Category: "ai",
		Targets: []Target{{Host: "www.figma.com", Path: "/"}},
		Domains: []string{"figma.com"},
	},
	// --- the web in general ---
	{
		ID: "cloudflare", Name: "Сайты на Cloudflare", Category: "web", Default: true,
		Targets: []Target{
			{Host: "speed.cloudflare.com", Path: "/__down?bytes=65536", MinBytes: 64 << 10},
			{Host: "www.cloudflare.com", Path: "/", MinBytes: 256 << 10},
			{Host: "cdnjs.cloudflare.com", Path: "/ajax/libs/jquery/3.7.1/jquery.min.js", MinBytes: 80000},
		},
		Note: "Провайдеры с июня 2025 года замедляют зарубежные сайты на Cloudflare: страница замирает после 16–20 КБ. Если не помогает, отключите ECH в браузере.",
	},
	{
		ID: "hosting", Name: "Сайты на зарубежном хостинге", Category: "web", Default: true,
		Targets: []Target{{Host: "fsn1-speed.hetzner.com", Path: "/100MB.bin", MinBytes: 64 << 10}},
		Note:    "Проверка скачивает 64 КБ с серверов Hetzner: так видно ограничение на зарубежный хостинг.",
	},
	{
		ID: "securedns", Name: "Защищённый DNS", Category: "web", Default: true, AnyOK: true,
		Targets: []Target{
			{Host: "dns.google", Path: "/resolve?name=youtube.com&type=A", MinBytes: 50},
			{Host: "cloudflare-dns.com", Path: "/dns-query?name=youtube.com&type=A", MinBytes: 50, Accept: "application/dns-json"},
			{Host: "dns.quad9.net", Path: "/"},
		},
		Note: "Нужен, чтобы браузер получал настоящие адреса заблокированных сайтов.",
	},
	{
		ID: "media", Name: "Независимые СМИ", Category: "web",
		Targets: []Target{{Host: "www.bbc.com", Path: "/"}, {Host: "meduza.io", Path: "/"}},
		Domains: []string{"bbc.com", "bbc.co.uk", "dw.com", "svoboda.org", "currenttime.tv", "themoscowtimes.com", "meduza.io", "novayagazeta.eu", "theins.ru"},
	},
	{
		ID: "patreon", Name: "Patreon", Category: "web",
		Targets: []Target{{Host: "www.patreon.com", Path: "/"}},
		Domains: []string{"patreon.com", "patreonusercontent.com"},
	},
}
