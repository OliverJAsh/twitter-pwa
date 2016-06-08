/// <reference path="../typings/main.d.ts" />
/// <reference path="../manual-typings/main.d.ts" />

// https://github.com/Microsoft/TypeScript/issues/3005
/// <reference path="../node_modules/typescript/lib/lib.es6.d.ts" />

import { Server, createServer } from 'http';
import * as express from 'express';
import fetch from 'node-fetch';
import { randomBytes as randomBytesCb } from 'crypto';
import * as denodeify from 'denodeify';
import { toPairs, sortBy } from 'lodash';
import { createHmac } from 'crypto';
import * as session from 'express-session';

const randomBytes = denodeify(randomBytesCb);

const app = express();

app.use(session({ secret: 'keyboard cat' }));

const twitterConsumerKey = process.env.TWITTER_CONSUMER_KEY;
const twitterConsumerSecret = process.env.TWITTER_CONSUMER_SECRET;
const twitterCallbackURL = 'http://127.0.0.1:8080/auth/callback';
const twitterApiURL = 'https://api.twitter.com';

// https://dev.twitter.com/oauth/overview/creating-signatures
const createOauthSignature = ({ method, baseUrl, parameters, oauthTokenSecret }: { method: string, baseUrl: string, parameters: {}, oauthTokenSecret: string }): string => {
    const parametersString = sortBy(
        toPairs(parameters)
            .map(([ key, value ]) => [ encodeURIComponent(key), encodeURIComponent(value) ]),
        ([ key, value ]) => key
    )
        .map(pair => pair.join('='))
        .join('&');

    const signatureBaseString = `${method}&${encodeURIComponent(baseUrl)}&${encodeURIComponent(parametersString)}`;
    const signingKey = `${encodeURIComponent(twitterConsumerSecret)}&${encodeURIComponent(oauthTokenSecret)}`
    const signature = createHmac('sha1', signingKey).update(signatureBaseString).digest('base64')

    return signature;
};

const createNonce = () => randomBytes(32).then(buffer => (
    buffer.toString('base64').replace(/[^\w]/g, '')
));

const oauthHeaderFromObj = (oauthParams: {}) => (
    toPairs(oauthParams)
        .map(([ key, value ]) => `${encodeURIComponent(key)}="${encodeURIComponent(value)}"`)
        .join(', ')
);

const getRequestToken = () => {
    return createNonce().then(nonce => {
        const oauthParams = {
            oauth_callback: twitterCallbackURL,
            oauth_consumer_key: twitterConsumerKey,
            oauth_nonce: nonce,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: parseInt((Date.now() / 1000).toFixed(0)),
            oauth_version: '1.0'
        };
        const baseUrl = `${twitterApiURL}/oauth/request_token`;
        const method = 'POST';
        const oauthSignature = createOauthSignature({
            method,
            baseUrl,
            parameters: oauthParams,
            oauthTokenSecret: ''
        });
        const oauthHeader = oauthHeaderFromObj(
            Object.assign({}, oauthParams, { oauth_signature: oauthSignature })
        );

        return fetch(baseUrl, {
            method,
            headers: { 'Authorization': `OAuth ${oauthHeader}` }
        })
            .then(response => response.text().then(text => {
                if (response.ok) {
                    const pairs = text
                        .split('&')
                        .map(item => item.split('='))
                    return {
                        oauthToken: pairs.find(([ key, value ]) => key === 'oauth_token')[1],
                        oauthTokenSecret: pairs.find(([ key, value ]) => key === 'oauth_token_secret')[1],
                        oauthCallbackConfirmed: pairs.find(([ key, value ]) => key === 'oauth_callback_confirmed')[1]
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            }))
    });
}

const getAccessToken = ({ oauthRequestToken, oauthVerifier }: { oauthRequestToken: string, oauthVerifier: string }) => {
    return createNonce().then(nonce => {
        const oauthParams = {
            oauth_callback: twitterCallbackURL,
            oauth_consumer_key: twitterConsumerKey,
            oauth_nonce: nonce,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: parseInt((Date.now() / 1000).toFixed(0)),
            oauth_version: '1.0',
            oauth_token: oauthRequestToken
        };
        const baseUrl = `${twitterApiURL}/oauth/access_token?oauth_verifier=${oauthVerifier}`;
        const method = 'POST';
        const oauthSignature = createOauthSignature({
            method,
            baseUrl,
            parameters: oauthParams,
            oauthTokenSecret: ''
        });
        const oauthHeader = oauthHeaderFromObj(
            Object.assign({}, oauthParams, { oauth_signature: oauthSignature })
        );

        return fetch(baseUrl, {
            method,
            headers: { 'Authorization': `OAuth ${oauthHeader}` }
        })
            .then(response => response.text().then(text => {
                if (response.ok) {
                    const pairs = text
                        .split('&')
                        .map(item => item.split('='))
                    return {
                        oauthToken: pairs.find(([ key, value ]) => key === 'oauth_token')[1],
                        oauthTokenSecret: pairs.find(([ key, value ]) => key === 'oauth_token_secret')[1],
                        userId: pairs.find(([ key, value ]) => key === 'user_id')[1],
                        screenName: pairs.find(([ key, value ]) => key === 'screen_name')[1],
                        xAuthExpires: pairs.find(([ key, value ]) => key === 'x_auth_expires')[1]
                    }
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${text}`)
                }
            }))
    });
};

const getTimeline = ({ oauthAccessToken, oauthAccessTokenSecret }: { oauthAccessToken: string, oauthAccessTokenSecret: string }) => {
    return createNonce().then(nonce => {
        const oauthParams = {
            oauth_callback: twitterCallbackURL,
            oauth_consumer_key: twitterConsumerKey,
            oauth_nonce: nonce,
            oauth_signature_method: 'HMAC-SHA1',
            oauth_timestamp: parseInt((Date.now() / 1000).toFixed(0)),
            oauth_version: '1.0',
            oauth_token: oauthAccessToken
        };
        const baseUrl = `${twitterApiURL}/1.1/statuses/home_timeline.json`;
        const method = 'GET';
        const oauthSignature = createOauthSignature({
            method,
            baseUrl,
            parameters: oauthParams,
            oauthTokenSecret: oauthAccessTokenSecret
        });
        const oauthHeader = oauthHeaderFromObj(
            Object.assign({}, oauthParams, { oauth_signature: oauthSignature })
        );

        return fetch(baseUrl, {
            method,
            headers: { 'Authorization': `OAuth ${oauthHeader}` }
        })
            .then(response => response.json().then(json => {
                if (response.ok) {
                    // TODO: Model json
                    return json;
                } else {
                    throw new Error(`Bad response from Twitter: ${response.status} ${json}`)
                }
            }))
    });
};

// https://dev.twitter.com/web/sign-in/implementing
app.get('/auth', (req, res, next) => {
    getRequestToken()
        .then(requestTokenResponse => (
            res
                .status(302)
                .location(`${twitterApiURL}/oauth/authenticate?oauth_token=${requestTokenResponse.oauthToken}`)
                .end()
        ))
        .catch(next);
});
app.get('/auth/callback', (req, res, next) => {
    getAccessToken({ oauthRequestToken: req.query.oauth_token, oauthVerifier: req.query.oauth_verifier })
        .then(accessTokenResponse => {
            // TODO:
            (<any>req.session).oauthAccessToken = accessTokenResponse.oauthToken;
            (<any>req.session).oauthAccessTokenSecret = accessTokenResponse.oauthTokenSecret;
            res.redirect('/');
        })
        .catch(next);
});
app.get('/', (req, res, next) => {
    // TODO: If logged in helper
    if ((<any>req.session).oauthAccessToken) {
        getTimeline({
            oauthAccessToken: (<any>req.session).oauthAccessToken,
            oauthAccessTokenSecret: (<any>req.session).oauthAccessTokenSecret
        })
            .then(tweets => {
                res.send((
                    `<ul>${tweets.map((tweet: any) => (
                        `<li>@${tweet.user.screen_name}: ${tweet.text}</li>`
                    )).join('')}</ul>`
                ));
            })
            .catch(next);
    } else {
        res.send('false');
    }
})

const onListen = (server: Server): void => {
    const { port } = server.address();

    console.log(`Server running on port ${port}`);
};

const httpServer = createServer(app);
httpServer.listen(8080, () => onListen(httpServer));
