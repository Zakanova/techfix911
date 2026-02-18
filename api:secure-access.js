// Combined security: IP + Time + Rate Limiting + Secret Key

const RATE_LIMITS = new Map();

// YOUR IP ADDRESSES
const ALLOWED_IPS = [
    '2601:207:0:b9b0:b983:9ef:c2aa:a6d8',  // Your IPv6
];

// CHANGE THIS TO A RANDOM STRING AFTER TESTING
const SECRET_KEY = 'tf911-secure-2024';

// California timezone: UTC-7 (PDT) or UTC-8 (PST)
const TIMEZONE_OFFSET = -7; // PDT (Mar-Nov). Use -8 for PST (Nov-Mar)
const ACCESS_START_HOUR = 14; // 2:00 PM California
const ACCESS_END_HOUR = 19;   // 7:00 PM California

export default function handler(req, res) {
    const clientIp = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
    const now = new Date();
    const utcHour = now.getUTCHours();
    const californiaHour = (utcHour + TIMEZONE_OFFSET + 24) % 24;
    const day = now.getUTCDay();
    
    console.log('Access:', { ip: clientIp, californiaHour, day });
    
    // Layer 1: Rate Limiting
    const attempts = RATE_LIMITS.get(clientIp) || { count: 0, lastAttempt: 0 };
    if (now.getTime() - attempts.lastAttempt > 3600000) attempts.count = 0;
    attempts.count++;
    attempts.lastAttempt = now.getTime();
    RATE_LIMITS.set(clientIp, attempts);
    
    if (attempts.count > 5) {
        return res.status(429).send(`<!DOCTYPE html><html><head><style>body{background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;}h1{color:#ff0040;font-size:3rem;}</style></head><body><div><h1>⏳</h1><h2>Rate Limited</h2><p>Too many attempts. Try again in 1 hour.</p></div></body></html>`);
    }
    
    // Layer 2: Secret Key Bypass
    const urlKey = new URL(req.url, `https://${req.headers.host}`).searchParams.get('key');
    if (urlKey === SECRET_KEY) {
        res.setHeader('Set-Cookie', `auth=${SECRET_KEY}; HttpOnly; Secure; SameSite=Strict; Max-Age=86400`);
        res.setHeader('Location', '/app.html');
        return res.status(302).end();
    }
    
    const cookieAuth = req.headers.cookie?.includes(`auth=${SECRET_KEY}`);
    if (cookieAuth) {
        res.setHeader('Location', '/app.html');
        return res.status(302).end();
    }
    
    // Layer 3: IP Whitelist
    const normalizedIp = clientIp.replace(/^::ffff:/, '');
    const isAllowed = ALLOWED_IPS.some(allowed => {
        if (allowed === normalizedIp || allowed === clientIp) return true;
        if (normalizedIp.includes(':') && allowed.includes(':')) {
            return normalizedIp.split(':').slice(0, 4).join(':') === allowed.split(':').slice(0, 4).join(':');
        }
        return false;
    });
    
    if (!isAllowed) {
        return res.status(404).send(`<!DOCTYPE html><html><head><style>body{background:#f5f5f5;color:#333;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;}h1{font-size:4rem;color:#999;}</style></head><body><div><h1>404</h1><h2>Page Not Found</h2></div></body></html>`);
    }
    
    // Layer 4: Time-based Access
    const isWeekday = day >= 1 && day <= 5;
    const isAccessHours = californiaHour >= ACCESS_START_HOUR && californiaHour < ACCESS_END_HOUR;
    
    if (!isWeekday || !isAccessHours) {
        return res.status(403).send(`<!DOCTYPE html><html><head><style>body{background:#0a0a0f;color:#fff;font-family:system-ui;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;}h1{color:#ff0040;font-size:4rem;}p{color:#666;}</style></head><body><div><h1>🔒</h1><h2>Outside Access Hours</h2><p>Monday-Friday</p><p style="color:#00f3ff;">2:00 PM - 7:00 PM (California Time)</p><p style="color:#666;font-size:0.9rem;margin-top:20px;">Current CA Time: ${californiaHour}:00</p></div></body></html>`);
    }
    
    res.setHeader('Location', '/app.html');
    res.status(302).end();
}