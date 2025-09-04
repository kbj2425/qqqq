// server.js - Node.js 프록시 서버
const express = require('express');
const cors = require('cors');
const axios = require('axios');
const cheerio = require('cheerio');
const path = require('path');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 3000;

// 미들웨어 설정
app.use(cors({
    origin: ['http://localhost:3000', 'https://your-domain.com'],
    credentials: true
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Rate limiting - DDoS 방지
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15분
    max: 100, // 최대 100개 요청
    message: {
        error: '너무 많은 요청이 발생했습니다. 잠시 후 다시 시도해주세요.'
    }
});

app.use('/api/', limiter);

// 정적 파일 제공 (프론트엔드)
app.use(express.static('public'));

// 프록시 API 엔드포인트
app.post('/api/proxy', async (req, res) => {
    try {
        const { url, method = 'GET', headers = {} } = req.body;

        // URL 검증
        if (!url || !isValidUrl(url)) {
            return res.status(400).json({
                success: false,
                error: '유효하지 않은 URL입니다.'
            });
        }

        // 차단된 URL 확인
        if (isBlockedUrl(url)) {
            return res.status(403).json({
                success: false,
                error: '이 URL은 차단되었습니다.'
            });
        }

        console.log(`프록시 요청: ${method} ${url}`);

        // axios 요청 설정
        const config = {
            method: method.toLowerCase(),
            url: url,
            timeout: 30000, // 30초 타임아웃
            maxRedirects: 5,
            headers: {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'ko-KR,ko;q=0.8,en-US;q=0.5,en;q=0.3',
                'Accept-Encoding': 'gzip, deflate',
                'DNT': '1',
                'Connection': 'keep-alive',
                'Upgrade-Insecure-Requests': '1',
                ...headers
            },
            responseType: 'arraybuffer', // 바이너리 데이터 처리
            validateStatus: function (status) {
                return status < 500; // 500 에러만 reject
            }
        };

        const response = await axios(config);
        
        // 컨텐츠 타입 확인
        const contentType = response.headers['content-type'] || '';
        
        let processedData;
        let processedContentType = contentType;

        if (contentType.includes('text/html')) {
            // HTML 컨텐츠 처리
            const htmlContent = response.data.toString('utf-8');
            processedData = processHtml(htmlContent, url);
            processedContentType = 'text/html; charset=utf-8';
        } else if (contentType.includes('text/css')) {
            // CSS 컨텐츠 처리
            const cssContent = response.data.toString('utf-8');
            processedData = processCss(cssContent, url);
            processedContentType = 'text/css; charset=utf-8';
        } else if (contentType.includes('application/javascript') || contentType.includes('text/javascript')) {
            // JavaScript 처리 (기본적으로 그대로 전달)
            processedData = response.data.toString('utf-8');
            processedContentType = 'application/javascript; charset=utf-8';
        } else {
            // 기타 컨텐츠 (이미지, 폰트 등)
            processedData = response.data;
        }

        // 응답 헤더 설정
        res.set({
            'Content-Type': processedContentType,
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0',
            'X-Frame-Options': 'ALLOWALL'
        });

        res.send(processedData);

    } catch (error) {
        console.error('프록시 에러:', error.message);
        
        let errorMessage = '웹사이트를 로드할 수 없습니다.';
        let statusCode = 500;

        if (error.code === 'ENOTFOUND') {
            errorMessage = '웹사이트를 찾을 수 없습니다.';
            statusCode = 404;
        } else if (error.code === 'ECONNREFUSED') {
            errorMessage = '웹사이트에 연결할 수 없습니다.';
            statusCode = 503;
        } else if (error.code === 'ETIMEDOUT') {
            errorMessage = '요청 시간이 초과되었습니다.';
            statusCode = 408;
        }

        res.status(statusCode).json({
            success: false,
            error: errorMessage
        });
    }
});

// HTML 처리 함수
function processHtml(html, baseUrl) {
    const $ = cheerio.load(html);
    const urlObj = new URL(baseUrl);
    const baseHost = `${urlObj.protocol}//${urlObj.host}`;

    // 모든 링크를 프록시를 통하도록 수정
    $('a[href]').each(function() {
        const href = $(this).attr('href');
        if (href) {
            const absoluteUrl = resolveUrl(href, baseUrl);
            $(this).attr('href', `/api/proxy?url=${encodeURIComponent(absoluteUrl)}`);
            $(this).attr('target', '_parent');
        }
    });

    // 이미지 소스 수정
    $('img[src]').each(function() {
        const src = $(this).attr('src');
        if (src) {
            const absoluteUrl = resolveUrl(src, baseUrl);
            $(this).attr('src', `/api/proxy?url=${encodeURIComponent(absoluteUrl)}`);
        }
    });

    // CSS 링크 수정
    $('link[rel="stylesheet"]').each(function() {
        const href = $(this).attr('href');
        if (href) {
            const absoluteUrl = resolveUrl(href, baseUrl);
            $(this).attr('href', `/api/proxy?url=${encodeURIComponent(absoluteUrl)}`);
        }
    });

    // JavaScript 소스 수정
    $('script[src]').each(function() {
        const src = $(this).attr('src');
        if (src) {
            const absoluteUrl = resolveUrl(src, baseUrl);
            $(this).attr('src', `/api/proxy?url=${encodeURIComponent(absoluteUrl)}`);
        }
    });

    // 폼 액션 수정
    $('form[action]').each(function() {
        const action = $(this).attr('action');
        if (action) {
            const absoluteUrl = resolveUrl(action, baseUrl);
            $(this).attr('action', `/api/proxy?url=${encodeURIComponent(absoluteUrl)}`);
        }
    });

    // Base URL 설정
    if (!$('base').length) {
        $('head').prepend(`<base href="${baseHost}/">`);
    }

    // 프록시 정보 주입
    $('head').append(`
        <script>
            // 프록시 헬퍼 함수들
            window.PROXY_BASE_URL = '${baseHost}';
            window.PROXY_CURRENT_URL = '${baseUrl}';
            
            // 새 창에서 열기 방지
            window.open = function(url, name, specs) {
                if (url) {
                    window.location.href = '/api/proxy?url=' + encodeURIComponent(url);
                }
                return null;
            };
        </script>
    `);

    return $.html();
}

// CSS 처리 함수
function processCss(css, baseUrl) {
    // URL() 함수 내의 상대 경로를 절대 경로로 변환
    return css.replace(/url\s*\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (match, quote, url) => {
        if (url.startsWith('data:') || url.startsWith('http')) {
            return match;
        }
        const absoluteUrl = resolveUrl(url, baseUrl);
        return `url(${quote}/api/proxy?url=${encodeURIComponent(absoluteUrl)}${quote})`;
    });
}

// URL 해결 함수
function resolveUrl(url, base) {
    try {
        return new URL(url, base).toString();
    } catch {
        return url;
    }
}

// URL 검증 함수
function isValidUrl(string) {
    try {
        const url = new URL(string);
        return ['http:', 'https:'].includes(url.protocol);
    } catch {
        return false;
    }
}

// 차단된 URL 확인
function isBlockedUrl(url) {
    const blockedDomains = [
        // 악성 사이트나 차단하고 싶은 도메인들
        'malware-site.com',
        'dangerous-site.net'
    ];
    
    try {
        const urlObj = new URL(url);
        return blockedDomains.some(domain => urlObj.hostname.includes(domain));
    } catch {
        return false;
    }
}

// GET 요청도 처리 (직접 URL 접근용)
app.get('/api/proxy', async (req, res) => {
    const { url } = req.query;
    
    if (!url) {
        return res.status(400).json({
            success: false,
            error: 'URL 파라미터가 필요합니다.'
        });
    }

    // POST 요청으로 변환하여 처리
    req.body = { url, method: 'GET' };
    return app._router.handle(req, res);
});

// 메인 페이지
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// 상태 확인 API
app.get('/api/status', (req, res) => {
    res.json({
        success: true,
        message: '프록시 서버가 정상적으로 작동 중입니다.',
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// 에러 핸들러
app.use((err, req, res, next) => {
    console.error('서버 에러:', err.stack);
    res.status(500).json({
        success: false,
        error: '서버 내부 오류가 발생했습니다.'
    });
});

// 404 핸들러
app.use((req, res) => {
    res.status(404).json({
        success: false,
        error: '요청한 리소스를 찾을 수 없습니다.'
    });
});

// 서버 시작
app.listen(PORT, () => {
    console.log(`🚀 프록시 서버가 포트 ${PORT}에서 실행 중입니다.`);
    console.log(`📍 http://localhost:${PORT}`);
});

// 우아한 종료 처리
process.on('SIGTERM', () => {
    console.log('서버를 종료하는 중...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('서버를 종료하는 중...');
    process.exit(0);
});
